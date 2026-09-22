# Fixture: intentionally vulnerable C service. FAKE data only.
// Expected findings: see expected-findings.md
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// SEC-01: format string — user data as the FORMAT argument (%n = write)
void log_request(const char *user_agent) {
    fprintf(stderr, user_agent);
}

// SEC-02: unchecked copy into fixed buffer
int parse_name(const char *input) {
    char name[32];
    strcpy(name, input); // SEC-03: strcpy — no bound
    return strcmp(name, "admin") == 0;
}

// SEC-04: shell command with concatenated user value
int run_report(const char *report_name) {
    char cmd[256];
    snprintf(cmd, sizeof cmd, "render-report %s", report_name);
    return system(cmd); // shell = injection
}

// SEC-05: integer overflow -> tiny alloc -> huge copy
int read_blob(const char *buf, unsigned int len) {
    char *out = malloc(len + 1); // wraps when len == UINT_MAX
    if (!out) return -1;
    memcpy(out, buf, len);
    out[len] = 0;
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 1) {
        log_request(argv[1]);   // SEC-01 sink reached from argv
        parse_name(argv[1]);    // SEC-02/03 sink reached from argv
        run_report(argv[1]);    // SEC-04 sink reached from argv
    }
    return 0;
}
