#include "../src/portlist.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void test_single_ports(void) {
    int *ports = NULL;
    size_t count = 0;
    int rc = parse_port_list("22,80,443", &ports, &count);
    assert(rc == 0);
    assert(count == 3);
    assert(ports[0] == 22);
    assert(ports[1] == 80);
    assert(ports[2] == 443);
    free(ports);
    printf("ok: test_single_ports\n");
}

static void test_range(void) {
    int *ports = NULL;
    size_t count = 0;
    int rc = parse_port_list("20-25", &ports, &count);
    assert(rc == 0);
    assert(count == 6);
    for (int i = 0; i < 6; i++) {
        assert(ports[i] == 20 + i);
    }
    free(ports);
    printf("ok: test_range\n");
}

static void test_mixed(void) {
    int *ports = NULL;
    size_t count = 0;
    int rc = parse_port_list("80,20-22,443", &ports, &count);
    assert(rc == 0);
    /* sorted + deduped: 20,21,22,80,443 */
    assert(count == 5);
    int expected[] = {20, 21, 22, 80, 443};
    for (size_t i = 0; i < count; i++) {
        assert(ports[i] == expected[i]);
    }
    free(ports);
    printf("ok: test_mixed\n");
}

static void test_dedup(void) {
    int *ports = NULL;
    size_t count = 0;
    int rc = parse_port_list("80,80,80,1-3,2", &ports, &count);
    assert(rc == 0);
    assert(count == 4); /* 1,2,3,80 */
    free(ports);
    printf("ok: test_dedup\n");
}

static void test_invalid_inputs(void) {
    int *ports = NULL;
    size_t count = 0;

    assert(parse_port_list("", &ports, &count) != 0);
    assert(parse_port_list("abc", &ports, &count) != 0);
    assert(parse_port_list("80-", &ports, &count) != 0);
    assert(parse_port_list("-80", &ports, &count) != 0);
    assert(parse_port_list("100-50", &ports, &count) != 0);
    assert(parse_port_list("0", &ports, &count) != 0);
    assert(parse_port_list("70000", &ports, &count) != 0);
    assert(parse_port_list(NULL, &ports, &count) != 0);
    printf("ok: test_invalid_inputs\n");
}

static void test_service_names(void) {
    assert(strcmp(port_service_name(22), "ssh") == 0);
    assert(strcmp(port_service_name(443), "https") == 0);
    assert(strcmp(port_service_name(99999 % 65536), "unknown") == 0 ||
           strcmp(port_service_name(1), "unknown") == 0);
    printf("ok: test_service_names\n");
}

int main(void) {
    test_single_ports();
    test_range();
    test_mixed();
    test_dedup();
    test_invalid_inputs();
    test_service_names();
    printf("\nAll portlist tests passed.\n");
    return 0;
}
