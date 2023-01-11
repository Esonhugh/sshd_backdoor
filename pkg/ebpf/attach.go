package ebpf

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf/link"
)

var FS = "/sys/fs/bpf"

var (
	ErrAlreadyAttached = fmt.Errorf("durdur is already attached to the interface")
)

// Attach loads the eBPF program and attaches it to the kernel.
func Attach(iface *net.Interface) error {
	e, err := newEBPF()
	if err != nil {
		return err
	}
	defer e.Close()

	return e.Attach(iface)
}

// Attach attaches eBPF program to the kernel.
func (e *EBPF) Attach(iface *net.Interface) error {
	if err := e.LoadAttachedLink(); err == nil {
		return fmt.Errorf(
			"%w: %s", ErrAlreadyAttached, iface.Name,
		)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   e.Objects.XdpDurdurDropFunc,
		Interface: iface.Index,
	})
	if err != nil {
		return err
	}

	if err := l.Pin(e.linkPinFile()); err != nil {
		return err
	}

	e.L = l
	return nil
}
