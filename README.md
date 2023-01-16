## sshd_backdoor

This Project is based on BlackHat USA 2021 and Defcon 29.

About Using ebpf technique, hijacking the process during sshd service getting the ~/.ssh/authorized_keys to authorize user logging and injecting our public key make our login successful.

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
make build
```
