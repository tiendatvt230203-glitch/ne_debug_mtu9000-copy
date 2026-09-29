#include "../../../inc/profile/profile_edit.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

enum policy_update_type {
    POLICY_UPDATE_ADD,
    POLICY_UPDATE_EDIT,
    POLICY_UPDATE_DELETE
};

static int policy_exists(const struct app_config *config, int db_id)
{
    for (int i = 0; i < config->policy_count; i++)
        if (config->policies[i].db_id == db_id)
            return 1;
    return 0;
}

static int policy_wire_id(const struct app_config *config, int db_id)
{
    for (int i = 0; i < config->policy_count; i++) {
        const struct crypto_policy *policy = &config->policies[i];
        if (policy->db_id == db_id &&
            policy->action == POLICY_ACTION_ENCRYPT_L2)
            return policy->id;
    }
    return 0;
}

static void collect_other_wire_ids(const struct app_config *config,
                                   int target_db_id, uint8_t used[256])
{
    memset(used, 0, 256);
    used[0] = 1;
    for (int i = 0; i < config->policy_count; i++) {
        const struct crypto_policy *policy = &config->policies[i];
        if (policy->db_id != target_db_id &&
            policy->action == POLICY_ACTION_ENCRYPT_L2 &&
            policy->id > 0 && policy->id < 256)
            used[policy->id] = 1;
    }
}

static int assign_target_wire_id(struct app_config *config,
                                 int new_db_id, int preferred_wire_id)
{
    uint8_t used[256];
    int wire_id = 0;
    int encrypt = 0;

    collect_other_wire_ids(config, new_db_id, used);
    for (int i = 0; i < config->policy_count; i++)
        if (config->policies[i].db_id == new_db_id &&
            config->policies[i].action == POLICY_ACTION_ENCRYPT_L2) {
            encrypt = 1;
            break;
        }

    if (encrypt && preferred_wire_id > 0 && preferred_wire_id < 256 &&
        !used[preferred_wire_id])
        wire_id = preferred_wire_id;
    if (encrypt && (wire_id <= 0 || wire_id >= 256 || used[wire_id]))
        wire_id = new_db_id > 0 && new_db_id < 256 && !used[new_db_id]
            ? new_db_id : 0;
    if (encrypt && !wire_id) {
        for (wire_id = 1; wire_id < 256 && used[wire_id]; wire_id++)
            ;
        if (wire_id == 256)
            return -ENOSPC;
    }

    for (int i = 0; i < config->policy_count; i++)
        if (config->policies[i].db_id == new_db_id)
            config->policies[i].id =
                config->policies[i].action == POLICY_ACTION_ENCRYPT_L2
                    ? wire_id : 0;
    return 0;
}

static int build_policy_update(const struct app_config *current,
                               const struct app_config *database,
                               int old_db_id, int new_db_id,
                               enum policy_update_type type,
                               struct app_config *next)
{
    int old_exists = policy_exists(current, old_db_id);
    int new_exists = new_db_id > 0 && policy_exists(database, new_db_id);

    if ((type == POLICY_UPDATE_ADD && (old_exists || !new_exists)) ||
        (type == POLICY_UPDATE_EDIT && (!old_exists || !new_exists)) ||
        (type == POLICY_UPDATE_DELETE && !old_exists))
        return -EINVAL;

    *next = *current;
    next->policy_count = 0;

    for (int i = 0; i < current->policy_count; i++) {
        if (current->policies[i].db_id == old_db_id)
            continue;
        next->policies[next->policy_count++] = current->policies[i];
    }

    if (type != POLICY_UPDATE_DELETE) {
        for (int i = 0; i < database->policy_count; i++) {
            if (database->policies[i].db_id != new_db_id)
                continue;
            if (next->policy_count >= MAX_CRYPTO_POLICIES)
                return -ENOSPC;
            next->policies[next->policy_count++] = database->policies[i];
        }
        if (assign_target_wire_id(next, new_db_id,
                                  old_db_id == new_db_id
                                      ? policy_wire_id(current, old_db_id) : 0))
            return -ENOSPC;
    }

    next->crypto_enabled = database->crypto_enabled;
    return 0;
}

static int apply_policy_update(struct core_runtime *runtime,
                               const struct app_config *database,
                               int old_db_id, int new_db_id,
                               enum policy_update_type type)
{
    struct app_config current;
    struct app_config next;
    int rc;

    if (!runtime || !database || old_db_id <= 0 ||
        database->profile_id <= 0 ||
        database->policy_count < 0 ||
        database->policy_count > MAX_CRYPTO_POLICIES)
        return -EINVAL;

    pthread_rwlock_rdlock(&runtime->config_lock);
    current = runtime->config;
    pthread_rwlock_unlock(&runtime->config_lock);

    if (!runtime->running || current.profile_id == 0)
        return -ENODEV;
    if (current.profile_id != database->profile_id)
        return -EBUSY;

    rc = build_policy_update(&current, database, old_db_id, new_db_id,
                             type, &next);
    if (rc)
        return rc;

    pthread_rwlock_wrlock(&runtime->config_lock);
    runtime->config.crypto_enabled = next.crypto_enabled;
    runtime->config.policy_count = next.policy_count;
    memcpy(runtime->config.policies, next.policies,
           sizeof(runtime->config.policies));
    pthread_rwlock_unlock(&runtime->config_lock);

    return 0;
}

int core_profile_add_policy(struct core_runtime *runtime,
                            const struct app_config *new_config,
                            int policy_db_id)
{
    int rc = apply_policy_update(runtime, new_config, policy_db_id,
                                 policy_db_id, POLICY_UPDATE_ADD);
    if (!rc)
        fprintf(stderr, "[PROFILE] policy added id=%d\n", policy_db_id);
    return rc;
}

int core_profile_edit_policy(struct core_runtime *runtime,
                             const struct app_config *new_config,
                             int old_policy_db_id,
                             int new_policy_db_id)
{
    int rc = apply_policy_update(runtime, new_config, old_policy_db_id,
                                 new_policy_db_id, POLICY_UPDATE_EDIT);
    if (!rc)
        fprintf(stderr, "[PROFILE] policy edited id=%d->%d\n",
                old_policy_db_id, new_policy_db_id);
    return rc;
}

int core_profile_delete_policy(struct core_runtime *runtime,
                               const struct app_config *new_config,
                               int policy_db_id)
{
    int rc = apply_policy_update(runtime, new_config, policy_db_id, 0,
                                 POLICY_UPDATE_DELETE);
    if (!rc)
        fprintf(stderr, "[PROFILE] policy deleted id=%d\n", policy_db_id);
    return rc;
}
