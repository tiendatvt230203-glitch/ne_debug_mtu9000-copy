#ifndef CORE_PROFILE_EDIT_H
#define CORE_PROFILE_EDIT_H

#include "../core_types.h"

int core_profile_add_policy(struct core_runtime *runtime,
                            const struct app_config *new_config,
                            int policy_db_id);
int core_profile_edit_policy(struct core_runtime *runtime,
                             const struct app_config *new_config,
                             int old_policy_db_id,
                             int new_policy_db_id);
int core_profile_delete_policy(struct core_runtime *runtime,
                               const struct app_config *new_config,
                               int policy_db_id);

#endif
