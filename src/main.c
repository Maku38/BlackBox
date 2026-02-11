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
void resolve_context(int pid, unsigned long long cgroup_id, char *dest, size_t len) {
    // 1. L1 Cache Hit?
    if (cgroup_id == last_cgroup_id && cgroup_id != 0) {
        strncpy(dest, last_context_cache, len);
        return;
    }

    char path[64];
    char buf[512];
    FILE *f;

    snprintf(path, sizeof(path), "/proc/%d/cgroup", pid);
    f = fopen(path, "r");
    
    // Default to HOST
    strncpy(dest, "HOST", len);
    
    if (f) {
        while (fgets(buf, sizeof(buf), f)) {
            char *start = NULL;
            // Match: 0::/system.slice/docker-<ID>.scope
            if ((start = strstr(buf, "docker-"))) {
                start += 7; // Skip "docker-"
                char *end = strchr(start, '.');
                if (end) *end = '\0';
                snprintf(dest, len, "[docker:%.12s]", start);
                break;
            } 
            // Match: K8s / Kubepods
            else if ((start = strstr(buf, "kubepods"))) {
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

    // 2. Update Cache
    last_cgroup_id = cgroup_id;
    strncpy(last_context_cache, dest, sizeof(last_context_cache));
}

// --- DUMP LOGIC ---
void dump_blackbox() {
    char filename[64];
    time_t now = time(NULL);
    snprintf(filename, sizeof(filename), "incident_%ld.json", now);
    
    FILE *f = fopen(filename, "w");
    if (!f) return;

    fprintf(f, "[\n");
    
    int start = full_loop ? log_head : 0;
    int count = full_loop ? HISTORY_SIZE : log_head;
    
    for (int i = 0; i < count; i++) {
        int idx = (start + i) % HISTORY_SIZE;
        struct recorded_event_t *rec = &event_log[idx];
        struct event_t *e = &rec->raw;
        
        char s_ip[16] = "0.0.0.0", d_ip[16] = "0.0.0.0";
        if (e->type == EVENT_TCP_CONNECT) {
            format_ip(e->saddr, s_ip, sizeof(s_ip));
            format_ip(e->daddr, d_ip, sizeof(d_ip));
        }

        fprintf(f, "  {\"time\": %llu, \"pid\": %d, \"comm\": \"%s\", \"context\": \"%s\", \"type\": %d, \"dest_ip\": \"%s\", \"dest_port\": %d}%s\n", 
                e->timestamp_ns, e->pid, e->comm, rec->context, e->type, d_ip, e->dport, 
                (i == count - 1) ? "" : ",");
    }
    fprintf(f, "]\n");
    fclose(f);
    printf("\n[!!!] BLACK BOX DUMPED TO: %s\n", filename);
}

// --- REAL-TIME RECORDING ---
int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct event_t *e = data;
    
    // 1. Resolve Context NOW (while process is alive)
    char ctx_str[64];
    resolve_context(e->pid, e->cgroup_id, ctx_str, sizeof(ctx_str));

    // 2. Write to Circular Buffer
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

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        return NULL;
    }
    
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(8080); // Default port

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        return NULL;
    }
    
    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        return NULL;
    }

    printf("[NETWORK] Agent listening for remote triggers on port 8080...\n");

    while(!exiting) {
        new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
        if (new_socket > 0) {
            printf("\n[NETWORK] Trigger command received from Control Plane!\n");
            
            trigger_dump = true; // Signal the main BPF loop to dump
            
            // NEW: Fully compliant HTTP/1.1 response with strict CRLF endings
            char *resp = "HTTP/1.1 200 OK\r\n"
                         "Content-Type: text/plain\r\n"
                         "Content-Length: 15\r\n"
                         "Connection: close\r\n\r\n"
                         "Dump Triggered\n";
            
            send(new_socket, resp, strlen(resp), 0);
            close(new_socket);
        }
    }
    return NULL;
}

int main(int argc, char **argv) {
    struct main_bpf *skel;
    struct ring_buffer *rb = NULL;

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