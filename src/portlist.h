#ifndef NETPROBE_PORTLIST_H
#define NETPROBE_PORTLIST_H

#include <stddef.h>

/* Parses a port spec like "22,80,443,8000-8100" into a sorted,
 * deduplicated array of ints. Returns 0 on success, -1 on invalid input.
 * On success, *out points to a malloc'd array (caller must free) and
 * *out_count is set to the number of ports. */
int parse_port_list(const char *spec, int **out, size_t *out_count);

/* Returns a short common-service name for a well-known port, or "unknown"
 * if not recognized. Never NULL. */
const char *port_service_name(int port);

#endif
