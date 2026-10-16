#!/bin/sh
# Agent shell wrapper (S3): runs the agent's commands as an unprivileged uid so the
# kernel can tell them apart from the platform's own egress.
#
# Why a wrapper around bash: the agent SDK executes the bare name "bash" through
# PATH lookup in the *platform's* PATH, so an env-var shim cannot change which
# binary runs. Replacing /usr/bin/bash in the image is the one seam that catches
# every agent command (and, because the uid is inherited, everything it spawns).
#
# It is deliberately inert for anything that is not the agent:
#   * ARTEX_AGENT_UID is set only in the agent's BashEnv (see server/egress_lockdown.go)
#   * it drops privileges only when started as root
# so platform-side callers keep behaving exactly as before.
set -e

AGENT_UID="${ARTEX_AGENT_UID:-}"
REAL_BASH="/usr/bin/bash.real"

if [ -n "$AGENT_UID" ] && [ "$(id -u)" = "0" ]; then
	exec setpriv \
		--reuid="$AGENT_UID" \
		--regid="$AGENT_UID" \
		--clear-groups \
		--inh-caps=-all \
		--no-new-privs \
		"$REAL_BASH" "$@"
fi

exec "$REAL_BASH" "$@"
