// src/main.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <string.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include "blackbox.h"
#include "main.skel.h"
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>

// --- FLIGHT RECORDER STORAGE ---
#define HISTORY_SIZE 10000 


// --- SECURITY & THREADING ---
char AUTH_TOKEN[64]; // NEW: Dynamically loaded, no longer hardcoded


// We need a richer struct for Userspace storage that holds the string
struct recorded_event_t {
    struct event_t raw;      // The kernel event
    char context[64];        // The resolved Container Name (e.g. "[docker:a1b2...]")
};

struct recorded_event_t event_log[HISTORY_SIZE];
int log_head = 0;
bool full_loop = false;

// --- OPTIMIZATION: Micro-Cache ---
// Processes generate events in bursts. We don't want to read /proc for every single syscall.
unsigned long long last_cgroup_id = 0;
char last_context_cache[64] = "HOST";

static volatile bool exiting = false;
static volatile bool trigger_dump = false;

void sig_handler(int sig) {
    if (sig == SIGUSR1) trigger_dump = true;
    else exiting = true;
}

void format_ip(unsigned int ip, char *buf, size_t len) {
    struct in_addr addr;
    addr.s_addr = ip;
    inet_ntop(AF_INET, &addr, buf, len);
}

// --- RESOLVER: PID -> Container Name ---
// Now uses the exact logic confirmed by your 'cat /proc/...' output
// --- L2 CGROUP CACHE ---
#define CACHE_SIZE 256
struct {
    unsigned long long id;
    char context[64];
} cgroup_cache[CACHE_SIZE];
int cache_head = 0;

void resolve_context(int pid, unsigned long long cgroup_id, char *dest, size_t len) {
    if (cgroup_id == 0) {
        strncpy(dest, "HOST", len);
        return;
    }

    // 1. Search the Cache (Defeats the TOCTOU race for fast-dying processes)
    for (int i = 0; i < CACHE_SIZE; i++) {
        if (cgroup_cache[i].id == cgroup_id) {
            strncpy(dest, cgroup_cache[i].context, len);
            return;
        }
    }

    // 2. Cache Miss. Try to read from /proc/
    char path[64];
    char buf[512];
    FILE *f;
    strncpy(dest, "HOST", len); // Default fallback

    snprintf(path, sizeof(path), "/proc/%d/cgroup", pid);
    f = fopen(path, "r");
    
    if (f) {
        while (fgets(buf, sizeof(buf), f)) {
            char *start = NULL;
            if ((start = strstr(buf, "docker-"))) {
                start += 7;
                char *end = strchr(start, '.');
                if (end) *end = '\0';
                snprintf(dest, len, "[docker:%.12s]", start);
                break;
            } else if ((start = strstr(buf, "kubepods"))) {
                 char *last_slash = strrchr(buf, '/');
                 if (last_slash) {
                     start = last_slash + 1;
                     if (strncmp(start, "crio-", 5) == 0) start += 5;
                     if (strncmp(start, "cri-containerd-", 15) == 0) start += 15;
                     char *end = strchr(start, '.');
                     if (end) *end = '\0';
                     snprintf(dest, len, "[k8s:%.12s]", start);
                     break;
                 }
            }
        }
        fclose(f);
    }

    // 3. Save to Cache for future fast-dying siblings
    cgroup_cache[cache_head].id = cgroup_id;
    strncpy(cgroup_cache[cache_head].context, dest, 64);
    cache_head = (cache_head + 1) % CACHE_SIZE;
}

// --- DUMP LOGIC ---
void dump_blackbox() {
    char filename[64];
    time_t now = time(NULL);
    snprintf(filename, sizeof(filename), "incident_%ld.json", now);
    
    FILE *f = fopen(filename, "w");
    if (!f) return;

    fprintf(f, "[\n");
    int count = full_loop ? HISTORY_SIZE : log_head;
    
    for (int i = 0; i < count; i++) {
        int idx = full_loop ? (log_head + i) % HISTORY_SIZE : i;
        struct recorded_event_t *rec = &event_log[idx];
        struct event_t *e = &rec->raw;

        char src_ip[16] = "", dst_ip[16] = "";
        
        if (e->type == 3) { // EVENT_TCP_CONNECT
            format_ip(e->saddr, src_ip, sizeof(src_ip));
            format_ip(e->daddr, dst_ip, sizeof(dst_ip));
        }

        fprintf(f, "  {\n");
        fprintf(f, "    \"timestamp\": %llu,\n", e->timestamp_ns);
        fprintf(f, "    \"pid\": %d,\n", e->pid);
        fprintf(f, "    \"uid\": %d,\n", e->uid);
        fprintf(f, "    \"comm\": \"%s\",\n", e->comm);
        fprintf(f, "    \"context\": \"%s\",\n", rec->context);
        
        if (e->type == 3) {
            fprintf(f, "    \"type\": \"network\",\n");
            fprintf(f, "    \"src_ip\": \"%s\",\n", src_ip);
            fprintf(f, "    \"dst_ip\": \"%s\",\n", dst_ip);
            fprintf(f, "    \"dport\": %d\n", e->dport);
        } else {
            fprintf(f, "    \"type\": \"process\"\n");
        }
        
        fprintf(f, "  }%s\n", (i == count - 1) ? "" : ",");
    }
    
    fprintf(f, "]\n");
    fclose(f);
    printf("\n[!!!] BLACK BOX DUMPED TO: %s\n", filename);
}

// --- REAL-TIME RECORDING ---
int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct event_t *e = data;
    char ctx_str[64];
    resolve_context(e->pid, e->cgroup_id, ctx_str, sizeof(ctx_str));

    // No mutex needed! This runs synchronously in the poll loop.
    memcpy(&event_log[log_head].raw, e, sizeof(struct event_t));
    strncpy(event_log[log_head].context, ctx_str, 64);
    
    log_head++;
    if (log_head >= HISTORY_SIZE) {
        log_head = 0;
        full_loop = true;
    }
    
    return 0;
}

// --- REMOTE CONTROL PLANE LISTENER ---
void *trigger_server(void *arg) {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[1024] = {0};

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) return NULL;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(8080);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) return NULL;
    if (listen(server_fd, 3) < 0) return NULL;

    printf("[NETWORK] Agent listening securely on port 8080...\n");

    while(!exiting) {
        new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
        if (new_socket > 0) {
            // Read the incoming HTTP request
            memset(buffer, 0, sizeof(buffer));
            recv(new_socket, buffer, sizeof(buffer) - 1, 0);
            
            // Check for the auth token in the request
            char expected_path[128];
            // FIXED: Added " HTTP/1." to prevent suffix injection bypass
            snprintf(expected_path, sizeof(expected_path), "GET /dump?token=%s HTTP/1.", AUTH_TOKEN);

            if (strstr(buffer, expected_path) != NULL) {
                printf("\n[NETWORK] Valid trigger received. Dumping...\n");
                trigger_dump = true;
                
                char *resp = "HTTP/1.1 200 OK\r\n"
                             "Content-Type: application/json\r\n"
                             "Connection: close\r\n\r\n"
                             "{\"status\": \"dumping\"}\n";
                send(new_socket, resp, strlen(resp), 0);
            } else {
                printf("\n[NETWORK] Unauthorized access attempt blocked.\n");
                char *resp = "HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n";
                send(new_socket, resp, strlen(resp), 0);
            }
            close(new_socket);
        }
    }
    return NULL;
}

int main(int argc, char **argv) {
    struct main_bpf *skel;
    struct ring_buffer *rb = NULL;

    // --- NEW: AUTH TOKEN INITIALIZATION ---
    char *env_token = getenv("BLACKBOX_AUTH_TOKEN");
    if (env_token) {
        strncpy(AUTH_TOKEN, env_token, sizeof(AUTH_TOKEN) - 1);
        AUTH_TOKEN[sizeof(AUTH_TOKEN) - 1] = '\0';
    } else {
        srand(time(NULL) ^ getpid());
        snprintf(AUTH_TOKEN, sizeof(AUTH_TOKEN), "dev_%d_%d", rand() % 10000, (int)time(NULL));
        printf("\n======================================================\n");
        printf("[WARNING] BLACKBOX_AUTH_TOKEN env var not set!\n");
        printf("[WARNING] Auto-generated temporary token: %s\n", AUTH_TOKEN);
        printf("======================================================\n\n");
    }

    skel = main_bpf__open();
    if (!skel) return 1;
    if (main_bpf__load(skel)) return 1;
    if (main_bpf__attach(skel)) return 1;

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) return 1;

    printf("Black Box Flight Recorder Active (v1.0 Production).\n");
    printf("PID: %d\n", getpid());
    
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGUSR1, sig_handler);

    // --- NEW: Start Network Listener ---
    pthread_t server_thread;
    if (pthread_create(&server_thread, NULL, trigger_server, NULL) != 0) {
        fprintf(stderr, "Failed to create network thread\n");
        return 1;
    }

    while (!exiting) {
        ring_buffer__poll(rb, 100);
        if (trigger_dump) {
            dump_blackbox();
            trigger_dump = false;
        }
    }

    ring_buffer__free(rb);
    main_bpf__destroy(skel);
    return 0;
}