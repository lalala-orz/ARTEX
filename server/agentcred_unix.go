//go:build !windows

package server

import (
	"os/exec"
	"syscall"
)

// applyAgentCredential runs cmd as the agent uid carried in env (ARTEX_AGENT_UID).
// Custom tools act for the agent, but they are spawned by the platform process and
// would otherwise leave as root — outside the kernel rule that intercepts the
// agent's own traffic. Dropping them into the same uid puts them back inside it.
// Returns false when no uid is configured (lockdown off), leaving cmd untouched.
func applyAgentCredential(cmd *exec.Cmd, env []string) bool {
	uid := agentUIDFromEnv(env)
	if uid <= 0 {
		return false
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(uid)},
	}
	return true
}
