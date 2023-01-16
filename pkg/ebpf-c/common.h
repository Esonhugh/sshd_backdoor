#ifndef COMMON_HEADER
#define COMMON_HEADER
#include <linux/vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define __EXPORTED_STRUCT __attribute__((unused));
#define __EXPORTED_DEFINE(exported_struct_name, useless_identifier) \
    const struct exported_struct_name * useless_identifier __EXPORTED_STRUCT;

inline size_t bd_check_current_tgid() {
    // Check this open call is opening our target file
    size_t pid_tgid = bpf_get_current_pid_tgid();
    // int pid = pid_tgid >> 32;
    unsigned int* pfd = bpf_map_lookup_elem(&map_fds, &pid_tgid);
    if (pfd == 0) {
        return 0;
    }
    return pid_tgid;
}

#endif