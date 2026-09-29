#include "../../../inc/runtime/runtime.h"
#include "../../../inc/runtime/worker.h"
#include "../../../inc/interface/interface.h"
#include "../../../inc/profile/profile_monitor.h"
#include "../../../inc/profile/profile_load.h"

#include "db_env.h"

#include <errno.h>
#include <libpq-fe.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>


static volatile sig_atomic_t g_shutdown;


/* =========================================================
 * Signal
 * ========================================================= */

static void runtime_signal(int signal_number)
{
    (void)signal_number;
    g_shutdown = 1;
}


/* =========================================================
 * Init
 * ========================================================= */

int core_runtime_init(struct core_runtime *runtime)
{
    if (!runtime)
        return -EINVAL;

    if (runtime->initialized)
        return 0;

    memset(runtime, 0, sizeof(*runtime));

    int rc =
        pthread_rwlock_init(&runtime->config_lock, NULL);

    if (rc)
        return -rc;

    atomic_init(&runtime->stop_requested, 0);

    runtime->initialized = 1;
    g_shutdown = 0;

    return 0;
}


/* =========================================================
 * Database
 * ========================================================= */

static PGconn *runtime_db_connect(void)
{
    struct ne_postgres_conn pg;

    if (ne_postgres_conn_fill(&pg))
        return NULL;

    PGconn *conn =
        PQconnectdbParams(pg.keywords,
                          pg.values,
                          0);

    if (!conn)
        return NULL;

    if (PQstatus(conn) != CONNECTION_OK) {
        PQfinish(conn);
        return NULL;
    }

    PGresult *result =
        PQexec(conn, "LISTEN xdp_start");

    int ok =
        result &&
        PQresultStatus(result) == PGRES_COMMAND_OK;

    if (result)
        PQclear(result);

    if (!ok) {
        PQfinish(conn);
        return NULL;
    }

    fprintf(stderr,
            "[DAEMON] ready; waiting -id <ID>\n");

    return conn;
}


/* =========================================================
 * Event
 * ========================================================= */

static void runtime_process_events(struct core_runtime *runtime,
                                   PGconn *conn)
{
    PGnotify *event;

    while (!g_shutdown &&
           (event = PQnotifies(conn))) {

        int rc =
            core_profile_monitor(runtime,
                                 event->extra);

        if (rc) {
            fprintf(stderr,
                    "[PROFILE] monitor failed payload=%s rc=%d\n",
                    event->extra,
                    rc);
        }

        PQfreemem(event);
    }
}


/* =========================================================
 * Run
 * ========================================================= */

int core_runtime_run(struct core_runtime *runtime)
{
    if (!runtime ||
        !runtime->initialized)
        return -EINVAL;

    struct sigaction action = {0};
    struct sigaction old_int;
    struct sigaction old_term;

    action.sa_handler = runtime_signal;
    sigemptyset(&action.sa_mask);

    if (sigaction(SIGINT,
                  &action,
                  &old_int))
        return -errno;

    if (sigaction(SIGTERM,
                  &action,
                  &old_term)) {

        int rc = -errno;

        sigaction(SIGINT,
                  &old_int,
                  NULL);

        return rc;
    }

    PGconn *conn = NULL;

    while (!g_shutdown) {

        if (!conn) {
            conn = runtime_db_connect();

            if (!conn) {
                poll(NULL, 0, 1000);
                continue;
            }
        }

        struct pollfd fd = {
            .fd = PQsocket(conn),
            .events = POLLIN
        };

        int ready =
            poll(&fd, 1, 500);

        if (ready < 0) {
            if (errno == EINTR)
                continue;

            PQfinish(conn);
            conn = NULL;
            continue;
        }

        if (ready == 0)
            continue;

        if (fd.revents &
            (POLLERR |
             POLLHUP |
             POLLNVAL)) {

            PQfinish(conn);
            conn = NULL;
            continue;
        }

        if (!PQconsumeInput(conn)) {
            PQfinish(conn);
            conn = NULL;
            continue;
        }

        runtime_process_events(runtime,
                               conn);
    }

    if (conn)
        PQfinish(conn);

    sigaction(SIGINT,
              &old_int,
              NULL);

    sigaction(SIGTERM,
              &old_term,
              NULL);

    return 0;
}


/* =========================================================
 * Stop
 * ========================================================= */

void core_runtime_stop(struct core_runtime *runtime)
{
    if (!runtime)
        return;

    g_shutdown = 1;

    atomic_store_explicit(
        &runtime->stop_requested,
        1,
        memory_order_release);
}


/* =========================================================
 * Cleanup
 * ========================================================= */

void core_runtime_cleanup(struct core_runtime *runtime)
{
    if (!runtime)
        return;

    core_profile_unload(runtime);

    if (runtime->initialized)
        pthread_rwlock_destroy(
            &runtime->config_lock);

    memset(runtime,
           0,
           sizeof(*runtime));
}