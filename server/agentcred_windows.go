//go:build windows

package server

import "os/exec"

// applyAgentCredential is a no-op on Windows: the egress lockdown is Linux-only
// (netfilter), so there is no uid to drop into.
func applyAgentCredential(*exec.Cmd, []string) bool { return false }
