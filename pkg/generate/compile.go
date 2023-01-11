// generated package contains auto compiled eBPF byte code.
// DO NOT EDIT any file under /internal/generated folder.
// Edit /internal/ebpf code to be able to change eBPF source code.
package generate

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -type $GENERATED_TYPE Bpf ../ebpf-c/xdp.c

// //go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc 'clang' -cflags ' -O2 -g -Wall -Werror -I /usr/include/aarch64-linux-gnu $(CFLAGS)' \
// // -type ${RINGBUF_EVENT_TYPE_OR_OTHER_YOU_WANT_EXPORTED} ${NAME_PREFIX_OF_ALL} ../ebpf-c/${c-source-code.c file}
