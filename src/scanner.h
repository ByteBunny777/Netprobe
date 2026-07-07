#ifndef NETPROBE_SCANNER_H
#define NETPROBE_SCANNER_H

#include <pthread.h>
#include <stddef.h>

#define BANNER_MAX 256

typedef struct {
    int port;
    int is_open;      /* 1 = open, 0 = closed/filtered */
    char banner[BANNER_MAX];
} ScanResult;

typedef struct {
    const char *host;        /* resolved target, as given by the user */
    const int *ports;        /* array of ports to scan */
    size_t port_count;
    ScanResult *results;      /* pre-sized array, one slot per port */
    int connect_timeout_ms;
    int banner_timeout_ms;
    int grab_banners;         /* 0/1 */
    size_t next_index;        /* shared cursor, protected by mutex */
    pthread_mutex_t mutex;
} ScanJob;

/* Runs the scan for `job` using `num_threads` worker threads and fills
 * job->results. Returns 0 on success, -1 on setup failure. */
int run_scan(ScanJob *job, int num_threads);

#endif
