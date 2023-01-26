package subCommand

import (
	ebpf "ebpf_common/pkg/ebpf-new"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var DetachCmd = &cobra.Command{
	Use:     "detach",
	Aliases: []string{"d"},
	Short:   "Detach ebpf program from file system.",
	Run: func(cmd *cobra.Command, args []string) {
		e := ebpf.New()
		var err error
		err = e.CreateCiliumEBPFRuntime(true)
		if err != nil {
			log.Panicln(err)
		}
		err = e.Detach()
		if err != nil {
			log.Panicln(err)
		}
		err = e.Close()
		if err != nil {
			log.Panicln(err)
		}
	},
}
