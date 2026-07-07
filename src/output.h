#ifndef NETPROBE_OUTPUT_H
#define NETPROBE_OUTPUT_H

#include "scanner.h"
#include <stddef.h>
#include <stdio.h>

typedef enum { OUTPUT_TEXT, OUTPUT_CSV, OUTPUT_JSON } OutputFormat;

/* Parses "text", "csv", or "json" (case-insensitive). Returns 0 on
 * success and sets *out, or -1 if the string doesn't match any format. */
int parse_output_format(const char *s, OutputFormat *out);

/* Writes results (only entries with is_open, unless show_closed is set)
 * to `stream` in the requested format. */
void write_results(FILE *stream, const char *host, const ScanResult *results,
                    size_t count, OutputFormat fmt, int show_closed);

#endif
