#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static volatile sig_atomic_t running = 1;
static volatile sig_atomic_t listener_descriptor = -1;

static void stop_server(int signal_number) {
    (void)signal_number;
    running = 0;
    if (listener_descriptor >= 0) {
        close((int)listener_descriptor);
        listener_descriptor = -1;
    }
}

static bool join_path(char *output, size_t capacity, const char *left, const char *right) {
    int written = snprintf(output, capacity, "%s/%s", left, right);
    return written > 0 && (size_t)written < capacity;
}

static bool state_path_from_args(int argc, char **argv, char *state, size_t capacity) {
    const char *data_dir = NULL;
    for (int index = 2; index + 1 < argc; index++) {
        if (strcmp(argv[index], "--data-dir") == 0) {
            data_dir = argv[index + 1];
            break;
        }
    }
    return data_dir != NULL
        && data_dir[0] == '/'
        && join_path(state, capacity, data_dir, "csswitch-installed-fake-science");
}

static int port_from_args(int argc, char **argv) {
    for (int index = 2; index + 1 < argc; index++) {
        if (strcmp(argv[index], "--port") == 0) {
            char *end = NULL;
            long value = strtol(argv[index + 1], &end, 10);
            if (end != NULL && *end == '\0' && value > 0 && value <= 65535 && value != 8765) {
                return (int)value;
            }
        }
    }
    return -1;
}

static bool write_private_file(const char *path, const char *value) {
    int descriptor = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
    if (descriptor < 0) {
        return false;
    }
    size_t remaining = strlen(value);
    const char *cursor = value;
    while (remaining > 0) {
        ssize_t written = write(descriptor, cursor, remaining);
        if (written <= 0) {
            close(descriptor);
            return false;
        }
        cursor += written;
        remaining -= (size_t)written;
    }
    bool ok = fsync(descriptor) == 0 && close(descriptor) == 0;
    return ok && chmod(path, 0600) == 0;
}

static bool write_all(int descriptor, const char *value, size_t length) {
    while (length > 0) {
        ssize_t written = write(descriptor, value, length);
        if (written <= 0) {
            return false;
        }
        value += written;
        length -= (size_t)written;
    }
    return true;
}

static const char *find_header(const char *request, const char *name) {
    size_t name_length = strlen(name);
    const char *line = strstr(request, "\r\n");
    if (line == NULL) {
        return NULL;
    }
    line += 2;
    while (*line != '\0' && strncmp(line, "\r\n", 2) != 0) {
        const char *end = strstr(line, "\r\n");
        if (end == NULL) {
            return NULL;
        }
        if ((size_t)(end - line) > name_length
            && strncasecmp(line, name, name_length) == 0
            && line[name_length] == ':') {
            const char *value = line + name_length + 1;
            while (value < end && (*value == ' ' || *value == '\t')) {
                value++;
            }
            return value;
        }
        line = end + 2;
    }
    return NULL;
}

static bool header_equals(const char *request, const char *name, const char *expected) {
    const char *value = find_header(request, name);
    if (value == NULL) {
        return false;
    }
    const char *end = strstr(value, "\r\n");
    return end != NULL
        && (size_t)(end - value) == strlen(expected)
        && strncmp(value, expected, strlen(expected)) == 0;
}

static bool header_contains(const char *request, const char *name, const char *expected) {
    const char *value = find_header(request, name);
    if (value == NULL) {
        return false;
    }
    const char *end = strstr(value, "\r\n");
    const char *match = strstr(value, expected);
    return end != NULL && match != NULL && match < end;
}

static size_t form_pair_count(
    const char *body,
    const char *name,
    const char *expected,
    const char *alternate
) {
    size_t matches = 0;
    size_t name_length = strlen(name);
    const char *pair = body;
    while (*pair != '\0') {
        const char *end = strchr(pair, '&');
        if (end == NULL) {
            end = pair + strlen(pair);
        }
        const char *equals = memchr(pair, '=', (size_t)(end - pair));
        if (equals != NULL
            && (size_t)(equals - pair) == name_length
            && strncmp(pair, name, name_length) == 0) {
            const char *value = equals + 1;
            size_t value_length = (size_t)(end - value);
            if ((value_length == strlen(expected)
                    && strncmp(value, expected, value_length) == 0)
                || (alternate != NULL
                    && value_length == strlen(alternate)
                    && strncmp(value, alternate, value_length) == 0)) {
                matches++;
            }
        }
        if (*end == '\0') {
            break;
        }
        pair = end + 1;
    }
    return matches;
}

static size_t form_name_count(const char *body, const char *name) {
    size_t matches = 0;
    size_t name_length = strlen(name);
    const char *pair = body;
    while (*pair != '\0') {
        const char *end = strchr(pair, '&');
        if (end == NULL) {
            end = pair + strlen(pair);
        }
        const char *equals = memchr(pair, '=', (size_t)(end - pair));
        if (equals != NULL
            && (size_t)(equals - pair) == name_length
            && strncmp(pair, name, name_length) == 0) {
            matches++;
        }
        if (*end == '\0') {
            break;
        }
        pair = end + 1;
    }
    return matches;
}

static ssize_t read_request(int descriptor, char *request, size_t capacity) {
    size_t used = 0;
    size_t target = 0;
    while (used + 1 < capacity) {
        ssize_t received = read(descriptor, request + used, capacity - used - 1);
        if (received <= 0) {
            return used > 0 ? (ssize_t)used : received;
        }
        used += (size_t)received;
        request[used] = '\0';
        const char *header_end = strstr(request, "\r\n\r\n");
        if (header_end == NULL) {
            continue;
        }
        if (target == 0) {
            target = (size_t)(header_end + 4 - request);
            const char *length_value = find_header(request, "Content-Length");
            if (length_value != NULL) {
                char *end = NULL;
                long length = strtol(length_value, &end, 10);
                if (end == length_value || length < 0 || length > 2048) {
                    return -1;
                }
                target += (size_t)length;
            }
        }
        if (used >= target) {
            return (ssize_t)used;
        }
    }
    return -1;
}

static bool send_json(
    int descriptor,
    int status,
    const char *status_text,
    const char *extra_headers,
    const char *body
) {
    char header[1024];
    int count = snprintf(
        header,
        sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "%s"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n\r\n",
        status,
        status_text,
        extra_headers,
        strlen(body)
    );
    return count > 0
        && (size_t)count < sizeof(header)
        && write_all(descriptor, header, (size_t)count)
        && write_all(descriptor, body, strlen(body));
}

static bool read_small_file(const char *path, char *value, size_t capacity) {
    int descriptor = open(path, O_RDONLY | O_NOFOLLOW);
    if (descriptor < 0) {
        return false;
    }
    ssize_t count = read(descriptor, value, capacity - 1);
    close(descriptor);
    if (count <= 0 || (size_t)count >= capacity) {
        return false;
    }
    value[count] = '\0';
    return true;
}

static bool state_file(char *output, size_t capacity, const char *state, const char *name) {
    return join_path(output, capacity, state, name);
}

static bool write_state(const char *state, int port, const char *executable) {
    char path[PATH_MAX];
    char value[PATH_MAX + 32];
    if (mkdir(state, 0700) != 0 && errno != EEXIST) {
        return false;
    }
    if (chmod(state, 0700) != 0) {
        return false;
    }
    if (!state_file(path, sizeof(path), state, "pid")) {
        return false;
    }
    snprintf(value, sizeof(value), "%d", getpid());
    if (!write_private_file(path, value)) {
        return false;
    }
    if (!state_file(path, sizeof(path), state, "port")) {
        return false;
    }
    snprintf(value, sizeof(value), "%d", port);
    if (!write_private_file(path, value)) {
        return false;
    }
    if (!state_file(path, sizeof(path), state, "executable")
        || !write_private_file(path, executable)) {
        return false;
    }
    if (!state_file(path, sizeof(path), state, "ready")
        || !write_private_file(path, "ready")) {
        return false;
    }
    return true;
}

static int run_server(const char *state, int port, const char *executable) {
    (void)setsid();
    int null_descriptor = open("/dev/null", O_RDWR);
    if (null_descriptor >= 0) {
        (void)dup2(null_descriptor, STDIN_FILENO);
        (void)dup2(null_descriptor, STDOUT_FILENO);
        (void)dup2(null_descriptor, STDERR_FILENO);
        if (null_descriptor > STDERR_FILENO) {
            close(null_descriptor);
        }
    }
    signal(SIGTERM, stop_server);
    signal(SIGINT, stop_server);

    int listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) {
        return 1;
    }
    int enabled = 1;
    (void)setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled));
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons((uint16_t)port);
    if (bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0
        || listen(listener, 8) != 0
        || !write_state(state, port, executable)) {
        close(listener);
        return 1;
    }
    listener_descriptor = listener;

    char origin[80];
    char auth_cookie[65];
    char cookie_header[256];
    char expected_cookie[96];
    if (snprintf(
            auth_cookie,
            sizeof(auth_cookie),
            "%064llx",
            (unsigned long long)getpid()
        ) != 64
        || snprintf(origin, sizeof(origin), "http://127.0.0.1:%d", port) <= 0
        || snprintf(
            cookie_header,
            sizeof(cookie_header),
            "Set-Cookie: operon_auth=%s; Path=/; HttpOnly; SameSite=Strict\r\n",
            auth_cookie
        ) <= 0
        || snprintf(
            expected_cookie,
            sizeof(expected_cookie),
            "operon_auth=%s",
            auth_cookie
        ) <= 0) {
        close(listener);
        return 1;
    }
    while (running) {
        int client = accept(listener, NULL, NULL);
        if (client < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        char request[4096];
        ssize_t received = read_request(client, request, sizeof(request));
        if (received <= 0) {
            close(client);
            continue;
        }
        request[received] = '\0';
        if (strncmp(request, "POST /api/auth/nonce ", 21) == 0) {
            const char *body = strstr(request, "\r\n\r\n");
            char nonce_path[PATH_MAX];
            char expected_nonce[65];
            bool valid = body != NULL
                && state_file(nonce_path, sizeof(nonce_path), state, "url-nonce")
                && read_small_file(nonce_path, expected_nonce, sizeof(expected_nonce))
                && header_equals(request, "Origin", origin)
                && form_name_count(body + 4, "nonce") == 1
                && form_pair_count(body + 4, "nonce", expected_nonce, NULL) == 1
                && form_name_count(body + 4, "dest") == 1
                && form_pair_count(body + 4, "dest", "%2F", "/") == 1;
            if (valid) {
                (void)send_json(client, 200, "OK", cookie_header, "{\"ok\":true}");
            } else {
                (void)send_json(
                    client,
                    401,
                    "Unauthorized",
                    "",
                    "{\"detail\":\"invalid bearer token\"}"
                );
            }
        } else if (strncmp(request, "GET /api/health ", 16) == 0) {
            bool valid = header_equals(request, "Origin", origin)
                && header_contains(request, "Cookie", expected_cookie);
            if (valid) {
                (void)send_json(
                    client,
                    200,
                    "OK",
                    "",
                    "{\"db_corruption\":{\"flagged\":false,\"kind\":null},"
                    "\"db_migrations_skipped\":false}"
                );
            } else {
                (void)send_json(
                    client,
                    401,
                    "Unauthorized",
                    "",
                    "{\"detail\":\"invalid bearer token\"}"
                );
            }
        } else {
            (void)send_json(
                client,
                200,
                "OK",
                "",
                "{\"status\":\"ok\",\"fake_science\":true}"
            );
        }
        close(client);
    }
    if (listener_descriptor >= 0) {
        close(listener);
        listener_descriptor = -1;
    }
    return 0;
}

static bool read_state_number(const char *state, const char *name, long *number) {
    char path[PATH_MAX];
    char value[64];
    if (!state_file(path, sizeof(path), state, name)
        || !read_small_file(path, value, sizeof(value))) {
        return false;
    }
    char *end = NULL;
    long parsed = strtol(value, &end, 10);
    if (end == NULL || *end != '\0') {
        return false;
    }
    *number = parsed;
    return true;
}

static void remove_state_files(const char *state) {
    const char *names[] = {"pid", "port", "executable", "ready"};
    char path[PATH_MAX];
    for (size_t index = 0; index < sizeof(names) / sizeof(names[0]); index++) {
        if (state_file(path, sizeof(path), state, names[index])) {
            (void)unlink(path);
        }
    }
}

static int serve_command(int argc, char **argv, const char *executable) {
    char state[PATH_MAX];
    int port = port_from_args(argc, argv);
    if (port < 0 || !state_path_from_args(argc, argv, state, sizeof(state))) {
        return 2;
    }
    remove_state_files(state);
    pid_t child = fork();
    if (child < 0) {
        return 1;
    }
    if (child > 0) {
        return 0;
    }
    _exit(run_server(state, port, executable));
}

static int status_command(int argc, char **argv) {
    char state[PATH_MAX];
    long pid = -1;
    long port = -1;
    bool ready = state_path_from_args(argc, argv, state, sizeof(state))
        && read_state_number(state, "pid", &pid)
        && read_state_number(state, "port", &port)
        && pid > 1 && port > 0 && port <= 65535
        && kill((pid_t)pid, 0) == 0;
    printf("{\"running\":%s}\n", ready ? "true" : "false");
    return 0;
}

static int url_command(int argc, char **argv) {
    char state[PATH_MAX];
    char path[PATH_MAX];
    char value[65];
    long count = 0;
    long port = -1;
    if (!state_path_from_args(argc, argv, state, sizeof(state))
        || !read_state_number(state, "port", &port)
        || port <= 0 || port > 65535) {
        return 1;
    }
    if (read_state_number(state, "url-count", &count) && count < LONG_MAX) {
        count++;
    } else {
        count = 1;
    }
    if (!state_file(path, sizeof(path), state, "url-count")) {
        return 1;
    }
    snprintf(value, sizeof(value), "%ld", count);
    if (!write_private_file(path, value)
        || !state_file(path, sizeof(path), state, "url-nonce")
        || snprintf(value, sizeof(value), "%064lx", (unsigned long)count) != 64
        || !write_private_file(path, value)) {
        return 1;
    }
    printf("http://127.0.0.1:%ld/?nonce=%s\n", port, value);
    return 0;
}

static int stop_command(int argc, char **argv, const char *executable) {
    char state[PATH_MAX];
    char path[PATH_MAX];
    char recorded_executable[PATH_MAX];
    long pid = -1;
    long port = -1;
    if (!state_path_from_args(argc, argv, state, sizeof(state))
        || !read_state_number(state, "pid", &pid)
        || !read_state_number(state, "port", &port)
        || !state_file(path, sizeof(path), state, "executable")
        || !read_small_file(path, recorded_executable, sizeof(recorded_executable))
        || pid <= 1 || port <= 0 || port > 65535
        || strcmp(recorded_executable, executable) != 0) {
        return 1;
    }
    const char *expected = getenv("CSSWITCH_EXPECTED_SANDBOX_PORT");
    if (expected != NULL && *expected != '\0' && strtol(expected, NULL, 10) != port) {
        return 1;
    }
    if (kill((pid_t)pid, SIGTERM) != 0 && errno != ESRCH) {
        return 1;
    }
    remove_state_files(state);
    puts("stopped");
    return 0;
}

int main(int argc, char **argv) {
    umask(0077);
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        puts("claude-science acceptance-native-fixture-1");
        return 0;
    }
    if (argc < 2) {
        return 2;
    }
    char executable[PATH_MAX];
    if (realpath(argv[0], executable) == NULL) {
        return 1;
    }
    if (strcmp(argv[1], "serve") == 0) {
        return serve_command(argc, argv, executable);
    }
    if (strcmp(argv[1], "status") == 0) {
        return status_command(argc, argv);
    }
    if (strcmp(argv[1], "url") == 0) {
        return url_command(argc, argv);
    }
    if (strcmp(argv[1], "stop") == 0) {
        return stop_command(argc, argv, executable);
    }
    return 2;
}
