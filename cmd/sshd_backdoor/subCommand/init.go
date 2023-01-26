package subCommand

import "ebpf_common/cmd/sshd_backdoor"

func init() {
	sshd_backdoor.RootCmd.AddCommand(AttachCmd, DetachCmd, SendKeyCmd)
}
