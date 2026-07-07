#include "portlist.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int port;
    const char *name;
} PortName;

/* Small static table of well-known ports. Not exhaustive on purpose --
 * covers what you actually run into on a home/office network audit. */
static const PortName KNOWN_PORTS[] = {
    {21, "ftp"},       {22, "ssh"},        {23, "telnet"},
    {25, "smtp"},      {53, "dns"},        {67, "dhcp"},
    {80, "http"},      {110, "pop3"},      {111, "rpcbind"},
    {123, "ntp"},      {135, "msrpc"},     {139, "netbios-ssn"},
    {143, "imap"},     {161, "snmp"},      {389, "ldap"},
    {443, "https"},    {445, "smb"},       {465, "smtps"},
    {587, "smtp-sub"}, {631, "ipp"},       {993, "imaps"},
    {995, "pop3s"},    {1433, "mssql"},    {1521, "oracle"},
    {2049, "nfs"},     {2375, "docker"},   {3000, "http-dev"},
    {3306, "mysql"},   {3389, "rdp"},      {5000, "http-dev"},
    {5432, "postgres"},{5900, "vnc"},      {5984, "couchdb"},
    {6379, "redis"},   {7000, "http-alt"}, {8000, "http-alt"},
    {8080, "http-alt"},{8443, "https-alt"},{8888, "http-alt"},
    {9000, "http-alt"},{9090, "http-alt"}, {9200, "elasticsearch"},
    {11211, "memcached"}, {27017, "mongodb"}, {6443, "kubernetes-api"},
};
static const size_t KNOWN_PORTS_COUNT = sizeof(KNOWN_PORTS) / sizeof(KNOWN_PORTS[0]);

const char *port_service_name(int port) {
    for (size_t i = 0; i < KNOWN_PORTS_COUNT; i++) {
        if (KNOWN_PORTS[i].port == port) {
            return KNOWN_PORTS[i].name;
        }
    }
    return "unknown";
}

static int cmp_int(const void *a, const void *b) {
    int ia = *(const int *)a;
    int ib = *(const int *)b;
    return ia - ib;
}

static int append_port(int **arr, size_t *count, size_t *capacity, int port) {
    if (port < 1 || port > 65535) {
        return -1;
    }
    if (*count == *capacity) {
        size_t new_cap = (*capacity == 0) ? 64 : (*capacity * 2);
        int *tmp = realloc(*arr, new_cap * sizeof(int));
        if (!tmp) {
            return -1;
        }
        *arr = tmp;
        *capacity = new_cap;
    }
    (*arr)[(*count)++] = port;
    return 0;
}

int parse_port_list(const char *spec, int **out, size_t *out_count) {
    if (!spec || !out || !out_count) {
        return -1;
    }

    int *arr = NULL;
    size_t count = 0, capacity = 0;

    char *spec_copy = strdup(spec);
    if (!spec_copy) {
        return -1;
    }

    char *saveptr = NULL;
    char *token = strtok_r(spec_copy, ",", &saveptr);
    int status = 0;

    while (token != NULL) {
        /* trim leading/trailing whitespace */
        while (*token == ' ' || *token == '\t') token++;
        char *end = token + strlen(token) - 1;
        while (end > token && (*end == ' ' || *end == '\t')) *end-- = '\0';

        char *dash = strchr(token, '-');
        if (dash != NULL) {
            *dash = '\0';
            char *start_str = token;
            char *end_str = dash + 1;
            if (*start_str == '\0' || *end_str == '\0') {
                status = -1;
                break;
            }
            char *endptr1 = NULL, *endptr2 = NULL;
            long start = strtol(start_str, &endptr1, 10);
            long end_v = strtol(end_str, &endptr2, 10);
            if (*endptr1 != '\0' || *endptr2 != '\0' || start > end_v) {
                status = -1;
                break;
            }
            for (long p = start; p <= end_v; p++) {
                if (append_port(&arr, &count, &capacity, (int)p) != 0) {
                    status = -1;
                    break;
                }
            }
            if (status != 0) break;
        } else {
            char *endptr = NULL;
            long p = strtol(token, &endptr, 10);
            if (*endptr != '\0' || *token == '\0') {
                status = -1;
                break;
            }
            if (append_port(&arr, &count, &capacity, (int)p) != 0) {
                status = -1;
                break;
            }
        }
        token = strtok_r(NULL, ",", &saveptr);
    }

    free(spec_copy);

    if (status != 0 || count == 0) {
        free(arr);
        return -1;
    }

    qsort(arr, count, sizeof(int), cmp_int);

    /* dedupe in place */
    size_t write_idx = 1;
    for (size_t i = 1; i < count; i++) {
        if (arr[i] != arr[write_idx - 1]) {
            arr[write_idx++] = arr[i];
        }
    }
    count = write_idx;

    *out = arr;
    *out_count = count;
    return 0;
}
