package ebpf

import (
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// newEBPF returns a new loaded EBPF.
func newEBPF() (*EBPF, error) {
	e := New()
	if err := e.Load(); err != nil {
		return nil, err
	}

	return e, nil
}

// newEBPFWithLink returns a new loaded EBPF by loading the link.
func newEBPFWithLink() (*EBPF, error) {
	e, err := newEBPF()
	if err != nil {
		return nil, err
	}

	if err := e.LoadAttachedLink(); err != nil {
		return nil, err
	}

	return e, nil
}

// LoadAttachedLink returns the pinned link from the FS.
func (e *EBPF) LoadAttachedLink() error {
	l, err := link.LoadPinnedLink(e.linkPinFile(), &ebpf.LoadPinOptions{})
	if err != nil {
		return fmt.Errorf("%s: %w", err, ErrAlreadyAttached)
	}

	e.L = l
	return nil
}

// linkPinFile returns FS file address for the link.
func (e *EBPF) linkPinFile() string {
	return fmt.Sprintf("%s/%s", FS, "xdp_drop_func_link")
}
