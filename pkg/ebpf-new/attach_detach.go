package ebpfnew

import (
	"fmt"
	"github.com/cilium/ebpf/link"
)

// Attach func create links map and make the program attached to the kernel.
func (c *CiliumEBPFRuntime) Attach() error {
	var err error
	c.Links[BPF_PROG_SYSCALL_ENTER_OPENAT], err = link.AttachTracing(link.TracingOptions{
		Program: c.Objects.HandleOpenatEnter,
	})
	c.Links[BPF_PROG_SYSCALL_EXIT_OPENAT], err = link.AttachTracing(link.TracingOptions{
		Program: c.Objects.HandleOpenatExit,
	})
	c.Links[BPF_PROG_SYSCALL_ENTER_READ], err = link.AttachTracing(link.TracingOptions{
		Program: c.Objects.HandleReadEnter,
	})
	c.Links[BPF_PROG_SYSCALL_EXIT_READ], err = link.AttachTracing(link.TracingOptions{
		Program: c.Objects.HandleReadExit,
	})

	if err != nil {
		return fmt.Errorf("attach link error: %w", err)
	}
	return nil
}

// DetachLinks func is used to detach links from kernel. and Unpin Maps. And After this call Close().
func (c *CiliumEBPFRuntime) Detach() error {
	var err error
	err = c.UnpinLinks()
	if err != nil {
		return fmt.Errorf("Unpin Links error: %w", err)
	}
	// Unpin Maps
	err = c.Objects.BpfMaps.MapPayloadBuffer.Unpin()
	if err != nil {
		return fmt.Errorf("Unpin MapPayloadBuffer error: %w", err)
	}
	return nil
}
