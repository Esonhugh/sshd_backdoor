package ebpfnew

import (
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	log "github.com/sirupsen/logrus"
)

// PinLinks func is used to pin links to filesystem.
func (c *CiliumEBPFRuntime) PinLinks() error {
	for k, v := range c.Links {
		err := v.Pin(FS + "/" + k)
		if err != nil {
			return fmt.Errorf("Pin %v error: %w", k, err)
		}
	}
	return nil
}

// InfoLinks func is used to print links info metadata
func (c *CiliumEBPFRuntime) InfoLinks() {
	for k, v := range c.Links {
		Info, err := v.Info()
		if err != nil {
			log.Debugf("Get link %v info error: %v", k, err)
		}
		log.Debugf("Got link %v info: %v", k, Info)
	}
}

// UnpinLinks func is used to unpin links from filesystem.
func (c *CiliumEBPFRuntime) UnpinLinks() error {
	for k, v := range c.Links {
		err := v.Unpin()
		if err != nil {
			return fmt.Errorf("Unpin %v error: %w", k, err)
		}
	}
	return nil
}

// CreatePinnedLink func will try load PinnedLinks or create new links with out attach process.
func (c *CiliumEBPFRuntime) CreatePinnedLink() error {
	var err error
	c.Links[BPF_PROG_SYSCALL_ENTER_OPENAT], err = link.LoadPinnedLink(BPF_PROG_FS_SYSCALL_ENTER_OPENAT, &ebpf.LoadPinOptions{})
	c.Links[BPF_PROG_SYSCALL_EXIT_OPENAT], err = link.LoadPinnedLink(BPF_PROG_FS_SYSCALL_EXIT_OPENAT, &ebpf.LoadPinOptions{})
	c.Links[BPF_PROG_SYSCALL_ENTER_READ], err = link.LoadPinnedLink(BPF_PROG_FS_SYSCALL_ENTER_READ, &ebpf.LoadPinOptions{})
	c.Links[BPF_PROG_SYSCALL_EXIT_READ], err = link.LoadPinnedLink(BPF_PROG_FS_SYSCALL_EXIT_READ, &ebpf.LoadPinOptions{})
	// c.Links[BPF_MAPS_PAYLOAD_BUFFER], err = link.LoadPinnedLink(BPF_MAPS_FS_PAYLOAD_BUFFER, &ebpf.LoadPinOptions{})
	if err != nil {
		return fmt.Errorf("load pinned link error: %w", err)
	}
	return nil
}

// CreateLink creates a link between a BPF program. There are attach process in link.Tracepoint
func (c *CiliumEBPFRuntime) CreateLink() error {
	var err error

	c.Links[BPF_PROG_SYSCALL_ENTER_OPENAT], err = link.Tracepoint(
		"syscalls", "sys_enter_openat", c.Objects.HandleOpenatEnter, nil)
	c.Links[BPF_PROG_SYSCALL_EXIT_OPENAT], err = link.Tracepoint(
		"syscalls", "sys_exit_openat", c.Objects.HandleOpenatExit, nil)
	c.Links[BPF_PROG_SYSCALL_ENTER_READ], err = link.Tracepoint(
		"syscalls", "sys_enter_read", c.Objects.HandleReadEnter, nil)
	c.Links[BPF_PROG_SYSCALL_EXIT_READ], err = link.Tracepoint(
		"syscalls", "sys_exit_read", c.Objects.HandleReadExit, nil)

	if err != nil { // any error occurred trigger this.
		return fmt.Errorf("link error: %w", err)
	}
	return nil
}
