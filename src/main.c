#include "output.h"
#include "portlist.h"
#include "scanner.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void print_usage(const char *prog) {
    fprintf(stderr,
        "netprobe - lightweight TCP port scanner for networks you own or are authorized to test\n\n"
        "Usage: %s -H <host> -p <ports> [options]\n\n"
        "Required:\n"
        "  -H, --host <host>       Target hostname or IP address\n"
        "  -p, --ports <spec>      Port(s), e.g. \"22,80,443\" or \"1-1024\" or \"20-25,80,8000-8100\"\n\n"
        "Options:\n"
        "  -t, --threads <n>       Number of worker threads (default: 50)\n"
        "  -w, --timeout <ms>      Connect timeout in milliseconds (default: 800)\n"
        "  -b, --banner-timeout <ms>  Banner read timeout in milliseconds (default: 500)\n"
        "  -n, --no-banner         Skip banner grabbing (faster, connect-only scan)\n"
        "  -a, --all                Also print closed/filtered ports (default: open only)\n"
        "  -o, --output <fmt>      Output format: text, csv, json (default: text)\n"
        "  -h, --help               Show this help\n\n"
        "Example:\n"
        "  %s -H 192.168.1.1 -p 1-1024 -t 100\n\n"
        "IMPORTANT: only scan hosts and networks you own or have explicit permission\n"
        "to test. Scanning systems without authorization may be illegal in your jurisdiction.\n",
        prog, prog);
}

int main(int argc, char **argv) {
    const char *host = NULL;
    const char *port_spec = NULL;
    int threads = 50;
    int connect_timeout_ms = 800;
    int banner_timeout_ms = 500;
    int grab_banners = 1;
    int show_closed = 0;
    OutputFormat fmt = OUTPUT_TEXT;

    static struct option long_opts[] = {
        {"host", required_argument, NULL, 'H'},
        {"ports", required_argument, NULL, 'p'},
        {"threads", required_argument, NULL, 't'},
        {"timeout", required_argument, NULL, 'w'},
        {"banner-timeout", required_argument, NULL, 'b'},
        {"no-banner", no_argument, NULL, 'n'},
        {"all", no_argument, NULL, 'a'},
        {"output", required_argument, NULL, 'o'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0},
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "H:p:t:w:b:nao:h", long_opts, NULL)) != -1) {
        switch (opt) {
            case 'H': host = optarg; break;
            case 'p': port_spec = optarg; break;
            case 't': threads = atoi(optarg); break;
            case 'w': connect_timeout_ms = atoi(optarg); break;
            case 'b': banner_timeout_ms = atoi(optarg); break;
            case 'n': grab_banners = 0; break;
            case 'a': show_closed = 1; break;
            case 'o':
                if (parse_output_format(optarg, &fmt) != 0) {
                    fprintf(stderr, "netprobe: unknown output format '%s'\n", optarg);
                    return 2;
                }
                break;
            case 'h': print_usage(argv[0]); return 0;
            default: print_usage(argv[0]); return 2;
        }
    }

    if (!host || !port_spec) {
        fprintf(stderr, "netprobe: --host and --ports are required\n\n");
        print_usage(argv[0]);
        return 2;
    }
    if (threads < 1 || threads > 2000) {
        fprintf(stderr, "netprobe: --threads must be between 1 and 2000\n");
        return 2;
    }

    int *ports = NULL;
    size_t port_count = 0;
    if (parse_port_list(port_spec, &ports, &port_count) != 0) {
        fprintf(stderr, "netprobe: invalid port spec '%s'\n", port_spec);
        return 2;
    }

    ScanResult *results = calloc(port_count, sizeof(ScanResult));
    if (!results) {
        fprintf(stderr, "netprobe: out of memory\n");
        free(ports);
        return 1;
    }

    ScanJob job = {
        .host = host,
        .ports = ports,
        .port_count = port_count,
        .results = results,
        .connect_timeout_ms = connect_timeout_ms,
        .banner_timeout_ms = banner_timeout_ms,
        .grab_banners = grab_banners,
        .next_index = 0,
    };

    fprintf(stderr, "netprobe: scanning %s (%zu ports, %d threads) -- only scan authorized targets\n",
            host, port_count, threads);

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    if (run_scan(&job, threads) != 0) {
        free(ports);
        free(results);
        return 1;
    }

    clock_gettime(CLOCK_MONOTONIC, &t1);
    double elapsed = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;

    write_results(stdout, host, results, port_count, fmt, show_closed);

    size_t open_count = 0;
    for (size_t i = 0; i < port_count; i++) {
        if (results[i].is_open) open_count++;
    }
    fprintf(stderr, "netprobe: done in %.2fs -- %zu/%zu ports open\n",
            elapsed, open_count, port_count);

    free(ports);
    free(results);
    return 0;
}
