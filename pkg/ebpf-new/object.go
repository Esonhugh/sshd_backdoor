package ebpfnew

import (
	"ebpf_common/pkg/generate"

	"github.com/cilium/ebpf/link"
)

type CilliumEBPFRuntime struct {
	Objects *generate.BpfObjects
	Links   []link.Link
}

func CreateCilliumEBPFRuntime() *CilliumEBPFRuntime {
	return &CilliumEBPFRuntime{
		Objects: &generate.BpfObjects{},
	}
}

func (c *CilliumEBPFRuntime) LoadBpf() {
}

func (c *CilliumEBPFRuntime) CreateLinks() {

}
