#ifndef COMMON_HEADER
#define COMMON_HEADER
#include <linux/vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define __EXPORTED_STRUCT __attribute__((unused));
#define __EXPORTED_DEFINE(exported_struct_name, useless_identifier) \
    const struct exported_struct_name * useless_identifier __EXPORTED_STRUCT;

#endif