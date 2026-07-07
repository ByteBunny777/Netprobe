#include "output.h"
#include "portlist.h"

#include <string.h>
#include <strings.h>

int parse_output_format(const char *s, OutputFormat *out) {
    if (!s || !out) return -1;
    if (strcasecmp(s, "text") == 0) { *out = OUTPUT_TEXT; return 0; }
    if (strcasecmp(s, "csv") == 0)  { *out = OUTPUT_CSV;  return 0; }
    if (strcasecmp(s, "json") == 0) { *out = OUTPUT_JSON; return 0; }
    return -1;
}

/* Escapes a quoted CSV field per RFC 4180: an embedded double quote is
 * written as two double quotes. Without this, a banner containing a
 * literal '"' (common in HTTP Server/WWW-Authenticate headers) closes
 * the quoted field early and the rest -- including any comma in the
 * banner -- gets misread as extra columns by any CSV parser. */
static void csv_escape(const char *in, char *out, size_t out_size) {
    size_t j = 0;
    for (size_t i = 0; in[i] != '\0'; i++) {
        char c = in[i];
        if (c == '"') {
            if (j + 2 >= out_size) break;
            out[j++] = '"';
            out[j++] = '"';
        } else {
            if (j + 1 >= out_size) break;
            out[j++] = c;
        }
    }
    out[j] = '\0';
}

/* Escapes double quotes for JSON string output. Truncates silently if
 * the banner is implausibly long (shouldn't happen given BANNER_MAX). */
static void json_escape(const char *in, char *out, size_t out_size) {
    size_t j = 0;
    for (size_t i = 0; in[i] != '\0' && j + 2 < out_size; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '"' || c == '\\') {
            out[j++] = '\\';
            out[j++] = (char)c;
        } else if (c >= 0x20 && c < 0x7f) {
            out[j++] = (char)c;
        }
        /* non-printable / non-ASCII bytes are dropped rather than
         * risking malformed JSON from a banner we don't control */
    }
    out[j] = '\0';
}

void write_results(FILE *stream, const char *host, const ScanResult *results,
                    size_t count, OutputFormat fmt, int show_closed) {
    if (fmt == OUTPUT_TEXT) {
        fprintf(stream, "%-8s %-8s %-16s %s\n", "PORT", "STATE", "SERVICE", "BANNER");
        for (size_t i = 0; i < count; i++) {
            const ScanResult *r = &results[i];
            if (!r->is_open && !show_closed) continue;
            fprintf(stream, "%-8d %-8s %-16s %s\n", r->port,
                    r->is_open ? "open" : "closed",
                    port_service_name(r->port),
                    r->banner);
        }
    } else if (fmt == OUTPUT_CSV) {
        char escaped[BANNER_MAX * 2];
        fprintf(stream, "host,port,state,service,banner\n");
        for (size_t i = 0; i < count; i++) {
            const ScanResult *r = &results[i];
            if (!r->is_open && !show_closed) continue;
            csv_escape(r->banner, escaped, sizeof(escaped));
            fprintf(stream, "%s,%d,%s,%s,\"%s\"\n", host, r->port,
                    r->is_open ? "open" : "closed",
                    port_service_name(r->port), escaped);
        }
    } else if (fmt == OUTPUT_JSON) {
        char escaped[BANNER_MAX * 2];
        fprintf(stream, "[\n");
        int first = 1;
        for (size_t i = 0; i < count; i++) {
            const ScanResult *r = &results[i];
            if (!r->is_open && !show_closed) continue;
            json_escape(r->banner, escaped, sizeof(escaped));
            fprintf(stream, "%s  {\"host\": \"%s\", \"port\": %d, \"state\": \"%s\", "
                            "\"service\": \"%s\", \"banner\": \"%s\"}",
                    first ? "" : ",\n", host, r->port,
                    r->is_open ? "open" : "closed",
                    port_service_name(r->port), escaped);
            first = 0;
        }
        fprintf(stream, "\n]\n");
    }
}
