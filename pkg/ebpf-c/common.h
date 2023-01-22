#ifndef __CILIUM_COMMON_HEADER
#define __CILIUM_COMMON_HEADER

#include <linux/vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

// This Macro is used to export useless struct in clang
// and make cilium bpf2go got custom defined type successfully.
#ifndef __CILIUM_GET_STRUCT_EXPORTED
#define __CILIUM_GET_STRUCT_EXPORTED

// __EXPORTED_STRUCT is alias of unused attribute.
#define __EXPORTED_STRUCT __attribute__((unused))

/*
    __EXPORTED_DEFINE(the struct name of you want exported, an useless identifier)
    e.g:
        struct event {
            int pid;
            char comm[TASK_COMM_LEN];
            bool success;
        };
    export this in cilium is using:


        const struct event * useless __attribute__((unused));


    now you just need:


        __EXPORTED_DEFINE(event, useless);
 */
#define __EXPORTED_DEFINE(exported_struct_name, useless_identifier) \
    const struct exported_struct_name *useless_identifier __EXPORTED_STRUCT

#endif

#ifndef __static_inline

// __always_inline is defined in bpf_helpers.h (libbpf)
#define __static_inline \
    static __always_inline
#endif

#endif
#ifndef max_payload_len 
#define max_payload_len 450
#endif