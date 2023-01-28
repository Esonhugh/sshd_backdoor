## sshd_backdoor

This Project is based on BlackHat USA 2021 and Defcon 29.

About Using ebpf technique, hijacking the process during sshd service getting the ~/.ssh/authorized_keys to authorize user logging and injecting our public key make our login successful.

### Demo

[![SSHD backdoor Demo](https://res.cloudinary.com/marcomontalbano/image/upload/v1674832434/video_to_markdown/images/youtube--2BUbPzwaGdk-c05b58ac6eb4c4700831b2b3070cd403.jpg)](https://youtu.be/2BUbPzwaGdk "SSHD backdoor Demo")

### Main Process in ebpf program

1. Hook OpenAt syscall enter: 
    check if the sshd process call this, log the pid of sshd.

2. Hook OpenAt Syscall exit:
    check the pid logged. logging the fd of pid, map pid->fd.

3. Hook Read Syscall enter:
    check the pid logged. logging the user_space_char_buffer of pid.

4. Hook Read Syscall exit:
    check the pid logged. find the buffer and change the buffer into our Key. Then delete pid in map to avoid blocking administrators' keys be read.

### Usage

```
$ make help

|=======================================================================================================
|usage:
|       build:  build full sshd_backdoor cli tool. But full sshd_backdoor is just supoorted the demo only
|       generate: Generate the ebpf prog in kernel with clang.
|                         if you need you can set the CFLAGS to append
|       test_ebpf: if you editing the ebpf-c c files and header files
|                          to test the ebpf can be compiled and pass ebpf verifier when load
|       tool_unload: bpftool unload progs.
|       tool_load: bpftool load  progs.
|       bpftrace_keylogging: logging sshd keys.Also it can catch the passwords when logging
|
```

## By the way

### sshd keylogging

```
make bpftrace_keylogging
```

which logging all message in sshd process. Of Course the key log.


### reference

https://github.com/pathtofile/bad-bpf/blob/main/src/sudoadd.bpf.c

https://www.youtube.com/watch?v=5zixNDolLrg

etc.
