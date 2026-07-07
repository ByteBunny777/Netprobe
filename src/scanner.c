#include "scanner.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <poll.h>

/* Attempts a non-blocking TCP connect to host:port within timeout_ms.
 * Returns a connected, blocking socket fd on success, or -1 on failure. */
static int try_connect(const struct addrinfo *ai, int timeout_ms) {
    int fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd < 0) {
        return -1;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        close(fd);
        return -1;
    }

    int rc = connect(fd, ai->ai_addr, ai->ai_addrlen);
    if (rc == 0) {
        /* Connected immediately (rare, e.g. localhost). Restore blocking mode. */
        fcntl(fd, F_SETFL, flags);
        return fd;
    }
    if (errno != EINPROGRESS) {
        close(fd);
        return -1;
    }

    struct pollfd pfd = { .fd = fd, .events = POLLOUT };
    int pret = poll(&pfd, 1, timeout_ms);
    if (pret <= 0) {
        close(fd); /* timeout or error */
        return -1;
    }

    int so_error = 0;
    socklen_t len = sizeof(so_error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &len) < 0 || so_error != 0) {
        close(fd);
        return -1;
    }

    fcntl(fd, F_SETFL, flags); /* back to blocking for the banner read */
    return fd;
}

/* Best-effort banner grab: reads whatever the service sends first, and
 * for common HTTP-ish ports, nudges it with a minimal request if it
 * stays silent. Never blocks longer than timeout_ms per attempt. */
static void grab_banner(int fd, int port, int timeout_ms, char *out, size_t out_size) {
    out[0] = '\0';

    struct timeval tv = { .tv_sec = timeout_ms / 1000, .tv_usec = (timeout_ms % 1000) * 1000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    ssize_t n = recv(fd, out, out_size - 1, 0);
    if (n <= 0 && (port == 80 || port == 8080 || port == 8000 || port == 8888 ||
                   port == 3000 || port == 5000 || port == 9000 || port == 9090)) {
        static const char req[] = "HEAD / HTTP/1.0\r\n\r\n";
        if (send(fd, req, sizeof(req) - 1, 0) > 0) {
            n = recv(fd, out, out_size - 1, 0);
        }
    }

    if (n > 0) {
        out[n] = '\0';
        /* keep only the first line -- enough to identify the service,
         * and avoids dumping a full HTTP response into the terminal */
        char *newline = strpbrk(out, "\r\n");
        if (newline) {
            *newline = '\0';
        }
    }
}

typedef struct {
    ScanJob *job;
    struct addrinfo *ai; /* resolved target, shared read-only across threads */
} WorkerArgs;

static void *worker_main(void *arg) {
    WorkerArgs *wargs = (WorkerArgs *)arg;
    ScanJob *job = wargs->job;

    for (;;) {
        pthread_mutex_lock(&job->mutex);
        size_t idx = job->next_index;
        if (idx >= job->port_count) {
            pthread_mutex_unlock(&job->mutex);
            break;
        }
        job->next_index++;
        pthread_mutex_unlock(&job->mutex);

        int port = job->ports[idx];
        ScanResult *res = &job->results[idx];
        res->port = port;
        res->is_open = 0;
        res->banner[0] = '\0';

        /* Patch the port into a copy of the resolved sockaddr */
        struct addrinfo ai_copy = *wargs->ai;
        char addr_buf[sizeof(struct sockaddr_storage)];
        memcpy(addr_buf, wargs->ai->ai_addr, wargs->ai->ai_addrlen);
        ai_copy.ai_addr = (struct sockaddr *)addr_buf;

        if (ai_copy.ai_family == AF_INET) {
            ((struct sockaddr_in *)addr_buf)->sin_port = htons((uint16_t)port);
        } else if (ai_copy.ai_family == AF_INET6) {
            ((struct sockaddr_in6 *)addr_buf)->sin6_port = htons((uint16_t)port);
        }

        int fd = try_connect(&ai_copy, job->connect_timeout_ms);
        if (fd >= 0) {
            res->is_open = 1;
            if (job->grab_banners) {
                grab_banner(fd, port, job->banner_timeout_ms, res->banner, BANNER_MAX);
            }
            close(fd);
        }
    }
    return NULL;
}

int run_scan(ScanJob *job, int num_threads) {
    if (!job || !job->host || job->port_count == 0 || num_threads < 1) {
        return -1;
    }

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *result = NULL;
    int gai_err = getaddrinfo(job->host, NULL, &hints, &result);
    if (gai_err != 0 || result == NULL) {
        fprintf(stderr, "netprobe: could not resolve host '%s': %s\n",
                job->host, gai_strerror(gai_err));
        return -1;
    }

    job->next_index = 0;
    pthread_mutex_init(&job->mutex, NULL);

    if ((size_t)num_threads > job->port_count) {
        num_threads = (int)job->port_count;
    }

    pthread_t *threads = malloc(sizeof(pthread_t) * (size_t)num_threads);
    WorkerArgs wargs = { .job = job, .ai = result };

    for (int i = 0; i < num_threads; i++) {
        pthread_create(&threads[i], NULL, worker_main, &wargs);
    }
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    free(threads);
    freeaddrinfo(result);
    pthread_mutex_destroy(&job->mutex);
    return 0;
}
