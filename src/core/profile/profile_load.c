#include "../../../inc/profile/profile_load.h"
#include "../../../inc/runtime/worker.h"
#include "../../../inc/interface/interface.h"
#include "db_runtime.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

static int profile_config_valid(const struct app_config *config)
{
    return config && config->profile_id > 0 &&
           config->local_count == 1 && config->wan_count == 1 &&
           config->bridge_count >= 0 && config->bridge_count <= 1 &&
           config->policy_count >= 0 &&
           config->policy_count <= MAX_CRYPTO_POLICIES;
}

int core_profile_load(struct core_runtime *runtime, int profile_id)
{
    struct app_config config;
    int rc;

    if (!runtime || profile_id <= 0)
        return -EINVAL;
    if (runtime->config.profile_id != 0 || runtime->running) {
        fprintf(stderr, "[PROFILE] id=%d is running; load id=%d refused\n",
                runtime->config.profile_id, profile_id);
        return -EBUSY;
    }

    memset(&config, 0, sizeof(config));
    rc = load_active_profile_config(&config, profile_id);
    if (rc)
        return rc;
    if (!profile_config_valid(&config) || config.profile_id != profile_id)
        return -EINVAL;

    runtime->config = config;
    rc = ne_pair_open(&runtime->pair, &runtime->config);
    if (rc)
        goto fail;

    rc = core_worker_start_all(runtime);
    if (rc) {
        ne_pair_close(&runtime->pair, &runtime->config);
        goto fail;
    }

    fprintf(stderr, "[PROFILE] loaded id=%d LAN=%s WAN=%s policies=%d\n",
            runtime->config.profile_id,
            runtime->config.locals[0].ifname,
            runtime->config.wans[0].ifname,
            runtime->config.policy_count);
    return 0;

fail:
    memset(&runtime->config, 0, sizeof(runtime->config));
    memset(runtime->workers, 0, sizeof(runtime->workers));
    runtime->worker_count = 0;
    runtime->running = 0;
    return rc;
}

void core_profile_unload(struct core_runtime *runtime)
{
    int was_active;

    if (!runtime)
        return;

    was_active = runtime->config.profile_id != 0 || runtime->running ||
                 runtime->pair.umem != NULL;
    core_worker_stop_all(runtime);
    ne_pair_close(&runtime->pair, &runtime->config);
    memset(&runtime->config, 0, sizeof(runtime->config));
    memset(runtime->workers, 0, sizeof(runtime->workers));
    runtime->worker_count = 0;
    runtime->running = 0;

    if (was_active)
        fprintf(stderr, "[PROFILE] unloaded; daemon ready\n");
}
