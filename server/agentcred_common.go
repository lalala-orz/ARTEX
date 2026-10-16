package server

import (
	"strconv"
	"strings"
)

// agentUIDFromEnv reads the uid the shell wrapper would use from an environment
// slice, so every path that spawns a process for the agent can share it.
func agentUIDFromEnv(env []string) int {
	for _, kv := range env {
		if rest, ok := strings.CutPrefix(kv, "ARTEX_AGENT_UID="); ok {
			if uid, err := strconv.Atoi(strings.TrimSpace(rest)); err == nil {
				return uid
			}
			return 0
		}
	}
	return 0
}
