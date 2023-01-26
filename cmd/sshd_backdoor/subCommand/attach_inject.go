package subCommand

import (
	ebpf "ebpf_common/pkg/ebpf-new"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var AttachCmd = &cobra.Command{
	Use:     "inject",
	Aliases: []string{"attach", "i", "a"},
	Short:   "Inject ebpf program into file system and keep it persist.",
	Run: func(cmd *cobra.Command, args []string) {
		e := ebpf.New()
		var err error
		err = e.CreateCiliumEBPFRuntime(false)
		if err != nil {
			log.Panicln(err)
		}
		err = e.Attach()
		if err != nil {
			log.Panicln(err)
		}
		err = e.PinLinks()
		if err != nil {
			log.Panicln(err)
		}
		err = e.Close()
		if err != nil {
			log.Panicln(err)
		}
	},
}
