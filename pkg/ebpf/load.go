package ebpf

import (
	"fmt"

	generate "ebpf_common/pkg/generate"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// EBPF keeps eBPF Objects(BpfPrograms, BpfMaps) and Link.
type EBPF struct {
	Objects *generate.BpfObjects
	L       link.Link
}

// New returns a new EBPF.
func New() *EBPF {
	return &EBPF{
		Objects: &generate.BpfObjects{},
	}
}

// Load loads pre-compiled eBPF program.
func (e *EBPF) Load() error {
	spec, err := generate.LoadBpf()
	if err != nil {
		return fmt.Errorf("load ebpf: %w", err)
	}

	// Load for Maps in C progam.
	spec.Maps["drop_from_addrs"].Pinning = ebpf.PinByName
	spec.Maps["drop_to_addrs"].Pinning = ebpf.PinByName
	spec.Maps["event_report_area"].Pinning = ebpf.PinByName
	if err := spec.LoadAndAssign(e.Objects, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: FS,
		},
	}); err != nil {
		return fmt.Errorf("load and assign: %w", err)
	}

	return nil
}

// Close cleans all resources.
func (e *EBPF) Close() error {
	if e.Objects != nil {
		if err := e.Objects.Close(); err != nil {
			return err
		}
	}

	if e.L != nil {
		if err := e.L.Close(); err != nil {
			return err
		}
	}

	return nil
}
