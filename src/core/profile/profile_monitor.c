#include "../../../inc/profile/profile_monitor.h"
#include "../../../inc/profile/profile_load.h"
#include "../../../inc/profile/profile_edit.h"
#include "db_runtime.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

static int parse_profile_id(const char *payload, int *profile_id)
{
    int used = 0;
    int id;

    if (sscanf(payload, "load:%d%n", &id, &used) != 1 ||
        id <= 0 || payload[used] != '\0')
        return -EINVAL;
    *profile_id = id;
    return 0;
}

static int policy_id_present(const struct app_config *config, int db_id)
{
    for (int i = 0; i < config->policy_count; i++)
        if (config->policies[i].db_id == db_id)
            return 1;
    return 0;
}

static int append_policy_id(int ids[MAX_CRYPTO_POLICIES], int *count, int id)
{
    for (int i = 0; i < *count; i++)
        if (ids[i] == id)
            return 0;
    if (*count >= MAX_CRYPTO_POLICIES)
        return -ENOSPC;
    ids[(*count)++] = id;
    return 0;
}

static int collect_policy_ids(const struct app_config *config,
                              int ids[MAX_CRYPTO_POLICIES])
{
    int count = 0;

    for (int i = 0; i < config->policy_count; i++)
        if (append_policy_id(ids, &count, config->policies[i].db_id))
            return -ENOSPC;
    return count;
}

static int policy_row_equal(const struct crypto_policy *a,
                            const struct crypto_policy *b)
{
    return a->priority == b->priority &&
           a->action == b->action &&
           a->protocol == b->protocol &&
           a->src_port_from == b->src_port_from &&
           a->src_port_to == b->src_port_to &&
           a->dst_port_from == b->dst_port_from &&
           a->dst_port_to == b->dst_port_to &&
           a->src_any == b->src_any &&
           a->dst_any == b->dst_any &&
           a->src_negate == b->src_negate &&
           a->dst_negate == b->dst_negate &&
           a->src_net == b->src_net &&
           a->src_mask == b->src_mask &&
           a->dst_net == b->dst_net &&
           a->dst_mask == b->dst_mask;
}

static int policy_equal(const struct app_config *current,
                        const struct app_config *database, int db_id)
{
    int current_rows[MAX_CRYPTO_POLICIES];
    int database_rows[MAX_CRYPTO_POLICIES];
    int current_count = 0;
    int database_count = 0;

    for (int i = 0; i < current->policy_count; i++)
        if (current->policies[i].db_id == db_id)
            current_rows[current_count++] = i;
    for (int i = 0; i < database->policy_count; i++)
        if (database->policies[i].db_id == db_id)
            database_rows[database_count++] = i;

    if (current_count != database_count)
        return 0;
    for (int i = 0; i < current_count; i++)
        if (!policy_row_equal(&current->policies[current_rows[i]],
                              &database->policies[database_rows[i]]))
            return 0;
    return 1;
}

static int sync_policies(struct core_runtime *runtime,
                         const struct app_config *database)
{
    struct app_config current;
    int current_ids[MAX_CRYPTO_POLICIES];
    int database_ids[MAX_CRYPTO_POLICIES];
    int deleted[MAX_CRYPTO_POLICIES];
    int added[MAX_CRYPTO_POLICIES];
    int current_count;
    int database_count;
    int deleted_count = 0;
    int added_count = 0;
    int rc;

    pthread_rwlock_rdlock(&runtime->config_lock);
    current = runtime->config;
    pthread_rwlock_unlock(&runtime->config_lock);

    current_count = collect_policy_ids(&current, current_ids);
    database_count = collect_policy_ids(database, database_ids);
    if (current_count < 0 || database_count < 0)
        return -ENOSPC;

    for (int i = 0; i < current_count; i++)
        if (!policy_id_present(database, current_ids[i]))
            deleted[deleted_count++] = current_ids[i];
    for (int i = 0; i < database_count; i++)
        if (!policy_id_present(&current, database_ids[i]))
            added[added_count++] = database_ids[i];

    if (deleted_count == 1 && added_count == 1) {
        rc = core_profile_edit_policy(runtime, database,
                                      deleted[0], added[0]);
        if (rc)
            return rc;
        deleted_count = 0;
        added_count = 0;
    }

    for (int i = 0; i < deleted_count; i++) {
        rc = core_profile_delete_policy(runtime, database, deleted[i]);
        if (rc)
            return rc;
    }
    for (int i = 0; i < added_count; i++) {
        rc = core_profile_add_policy(runtime, database, added[i]);
        if (rc)
            return rc;
    }

    for (int i = 0; i < database_count; i++) {
        int id = database_ids[i];
        if (!policy_id_present(&current, id))
            continue;
        if (policy_equal(&current, database, id))
            continue;
        rc = core_profile_edit_policy(runtime, database, id, id);
        if (rc)
            return rc;
    }
    return 0;
}

int core_profile_monitor(struct core_runtime *runtime, const char *payload)
{
    struct app_config database;
    int profile_id;
    int rc;

    if (!runtime || !payload)
        return -EINVAL;
    rc = parse_profile_id(payload, &profile_id);
    if (rc)
        return rc;

    if (runtime->config.profile_id == 0)
        return core_profile_load(runtime, profile_id);
    if (runtime->config.profile_id != profile_id) {
        fprintf(stderr, "[PROFILE] id=%d is running; id=%d refused\n",
                runtime->config.profile_id, profile_id);
        return -EBUSY;
    }

    rc = ne_profile_id_exists(profile_id);
    if (rc == -ENOENT) {
        core_profile_unload(runtime);
        return 0;
    }
    if (rc)
        return rc;

    memset(&database, 0, sizeof(database));
    rc = load_active_profile_config(&database, profile_id);
    if (rc)
        return rc;

    return sync_policies(runtime, &database);
}
