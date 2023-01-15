SEC("tp/syscalls/sys_exit_close")
int handle_close_exit(struct trace_event_raw_sys_exit *ctx)
{
    // Check if we're a process thread of interest
    size_t pid_tgid = bpf_get_current_pid_tgid();
    // int pid = pid_tgid >> 32;
    unsigned int* check = bpf_map_lookup_elem(&map_fds, &pid_tgid);
    if (check == 0) {
        return 0;
    }

    // Closing file, delete fd from all maps to clean up
    bpf_map_delete_elem(&map_fds, &pid_tgid);
    bpf_map_delete_elem(&map_buff_addrs, &pid_tgid);

    return 0;
}