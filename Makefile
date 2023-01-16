CLANG ?= clang
CFLAGS := -O2 -g -Wall -Werror -I /usr/include/aarch64-linux-gnu $(CFLAGS)
GOPROXY := 'https://goproxy.io,direct'
GENERATED_TYPE := event

generate: mod_tidy
generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLAGS := $(CFLAGS)
generate: export GENERATED_TYPE := $(GENERATED_TYPE)
generate:
	go generate ./pkg/generate...

mod_tidy: export GOPROXY := $(GOPROXY)
mod_tidy: 
	go mod tidy

bpftrace_sshd:
	bpftrace test/bpftrace/sshd_open_read_watch_dog.bpftrace

bpftrace_keylogging:
	bpftrace test/bpftrace/sshd_keylogging.bt

bpftrace_verbose_keylogging:
	bpftrace test/bpftrace/sshd_keylogging_verbose.bt
