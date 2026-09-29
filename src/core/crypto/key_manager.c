#include "../../../inc/crypto/key_manager.h"
#include "../../../inc/core_types.h"

#include <errno.h>
#include <pthread.h>
#include <string.h>



static uint8_t g_key[CORE_KEY_SIZE] = {
    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a
};
static pthread_mutex_t g_keys_lock = PTHREAD_MUTEX_INITIALIZER;

static int key_policy_valid(int policy_id)
{
    return policy_id > 0 && policy_id < 256;
}

int core_key_install(int policy_id, const uint8_t *key, size_t key_size)
{
    if (!key_policy_valid(policy_id) || !key ||
        key_size != CORE_KEY_SIZE)
        return -EINVAL;
    pthread_mutex_lock(&g_keys_lock);
    memcpy(g_key, key, key_size);
    pthread_mutex_unlock(&g_keys_lock);
    return 0;
}

int core_key_get(int policy_id, uint8_t *key, size_t key_size)
{
    if (!key_policy_valid(policy_id) || !key || key_size != CORE_KEY_SIZE)
        return -EINVAL;
    pthread_mutex_lock(&g_keys_lock);
    memcpy(key, g_key, key_size);
    pthread_mutex_unlock(&g_keys_lock);
    return 0;
}
