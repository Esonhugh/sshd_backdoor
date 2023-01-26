package sshd_backdoor

import (
	_ "embed"
	"github.com/spf13/cobra"
)

//go:embed banner
var Banner string

var RootCmd = &cobra.Command{
	Use:   "ssh_bd",
	Short: Banner,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// For Sure this will run.
	},
}
