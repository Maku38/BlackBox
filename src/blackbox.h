// src/blackbox.h
#ifndef __BLACKBOX_H
#define __BLACKBOX_H

#define TASK_COMM_LEN 16

enum event_type {
    EVENT_EXEC = 1,
    EVENT_EXIT = 2,
    EVENT_TCP_CONNECT = 3
};

struct event_t {
    // Header
    unsigned long long timestamp_ns;
    unsigned long long cgroup_id;
    unsigned int pid;
    unsigned int ppid;
    unsigned int uid;
    char comm[TASK_COMM_LEN];
    
    // Payload
    int type; // EXEC or TCP_CONNECT
    unsigned int saddr; // Source IP (IPv4)
    unsigned int daddr; // Dest IP (IPv4)
    unsigned short sport; // Source Port
    unsigned short dport; // Dest Port
};

#endif