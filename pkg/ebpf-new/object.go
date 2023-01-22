package ebpfnew

import (
	"ebpf_common/pkg/generate"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type CilliumEBPFRuntime struct {
	Objects generate.BpfObjects
	Links   []link.Link
}

func RemoveMemoryLimit() error {
	return rlimit.RemoveMemlock()
}

func CreateCilliumEBPFRuntime() (*CilliumEBPFRuntime, error) {
	var BpfObjects generate.BpfObjects
	err := generate.LoadBpfObjects(&BpfObjects, nil)
	if err != nil {
		return nil, fmt.Errorf("load ebpf Objects error: %w", err)
	}
	return &CilliumEBPFRuntime{
		Objects: BpfObjects,
		Links:   []link.Link{},
	}, nil
}
