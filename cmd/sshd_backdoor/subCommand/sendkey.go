package subCommand

import (
	ebpf "ebpf_common/pkg/ebpf-new"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var SendKeyCmd = &cobra.Command{
	Use:     "send",
	Aliases: []string{"s"},
	Short:   `Send key to sshd process.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 1 {
			log.Println("Error needs arg of ssh key")
			return
		}
		e := ebpf.New()
		var err error
		err = e.CreateCiliumEBPFRuntime(true)
		if err != nil {
			log.Panicln(err)
		}
		err = e.SendKey(args[0])
		if err != nil {
			log.Panicln(err)
		}
		err = e.Close()
		if err != nil {
			log.Panicln(err)
		}
	},
}
