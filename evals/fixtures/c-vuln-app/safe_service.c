// SAFE counter-examples for c-vuln-app. An audit must NOT report these.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void log_request_safe(const char *user_agent) {
    // SAFE (vs SEC-01): format string is a literal; user data is an argument
    fprintf(stderr, "%s", user_agent);
}

int parse_name_safe(const char *input) {
    // SAFE (vs SEC-02/03): bounded copy with explicit size match
    char name[32];
    if (strlen(input) >= sizeof name) return 0;
    memcpy(name, input, strlen(input) + 1);
    return strcmp(name, "admin") == 0;
}

int run_report_safe(const char *report_name) {
    // SAFE (vs SEC-04): validated against an allowlist, execvp without shell
    static const char *const ALLOWED[] = {"daily", "weekly", NULL};
    for (int i = 0; ALLOWED[i]; i++) {
        if (strcmp(report_name, ALLOWED[i]) == 0) {
            char *const argv[] = {(char *)"render-report", (char *)ALLOWED[i], NULL};
            execvp(argv[0], argv);
        }
    }
    return -1;
}

int read_blob_safe(const char *buf, size_t len) {
    // SAFE (vs SEC-05): overflow-checked size arithmetic (size_t + explicit)
    if (len == 0 || len > (size_t)-1 - 1) return -1;
    char *out = malloc(len + 1);
    if (!out) return -1;
    memcpy(out, buf, len);
    out[len] = 0;
    free(out);
    return 0;
}
