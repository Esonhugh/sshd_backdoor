package ebpfnew

import (
	"ebpf_common/pkg/generate"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type CiliumEBPFRuntime struct {
	// Objects contains bpf maps progs etc..
	Objects *generate.BpfObjects
	// Links is the link between bpf program and bpf map.
	Links map[string]link.Link
}

// RemoveMemoryLimit func is alias of rlimit.RemoveMemoryLimit()
func (c *CiliumEBPFRuntime) RemoveMemoryLimit() error {
	return rlimit.RemoveMemlock()
}

/*
 *	LoadBpfObjects func overwrite generate.LoadBpfObjects() func. There are contains custom Pinning process of maps.
 *
 */
func (c *CiliumEBPFRuntime) LoadBpfObjects(opts *ebpf.CollectionOptions) error {
	spec, err := generate.LoadBpf()
	if err != nil {
		return err
	}

	// map Pinning
	spec.Maps[BPF_MAPS_PAYLOAD_BUFFER].Pinning = ebpf.PinByName

	return spec.LoadAndAssign(c.Objects, opts)
}

// CreateCiliumEBPFRuntime func will create links and load BPF objects in system.
// if used
func (c *CiliumEBPFRuntime) CreateCiliumEBPFRuntime(isAlreadyPinned bool) error {
	// var BpfObjects generate.BpfObjects
	//err := generate.LoadBpfObjects(&BpfObjects, &ebpf.CollectionOptions{
	err := c.LoadBpfObjects(&ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: FS,
		},
	})
	if err != nil {
		return fmt.Errorf("load ebpf Objects error: %w", err)
	}
	if isAlreadyPinned {
		// err = c.CreateLink()
		err = c.CreatePinnedLink()
		if err != nil {
			return fmt.Errorf("create link error: %w", err)
		}
	}
	return nil
}

// Close func closes all Objects in c.Objects and all Links in c.Links. Only Close().
func (c *CiliumEBPFRuntime) Close() error {
	if c.Objects != nil {
		if err := c.Objects.Close(); err != nil {
			return err
		}
	}
	if c.Links != nil {
		for _, eachLink := range c.Links {
			if err := eachLink.Close(); err != nil {
				return fmt.Errorf("Link close error: %w\n", eachLink.Close())
			}
		}
	}
	return nil
}
