package server

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Agent egress control.
//
// The listener is only a real chokepoint if the agent's commands cannot reach a
// target any other way. Environment variables cannot promise that — a raw socket,
// nmap or a library that ignores the proxy goes straight out. So every task's
// shell runs as its own unprivileged uid, and the kernel confines that uid's
// egress into the listener. The platform keeps running as root, which is what
// exempts its own egress (LLM calls, the tunnel's control channel, the listener
// itself) without any exception list.
//
// The uid doubles as identity: with a per-task uid the listener can tell which
// task a transparent connection belongs to (SO_PEERCRED), which is what keeps the
// per-task egress routing working once SOCKS5 usernames are out of the picture.

const (
	// agentUID is used where there is no task context (the chat agent).
	agentUID = 1001
	// Per-task uids are allocated from this range, so the kernel rules can match
	// them with a single range expression. Kept clear of the system ranges.
	agentUIDBase = 20000
	agentUIDMax  = 29999
)

// settingAgentEgressLockdown persists the toggle (default off: an existing
// install keeps behaving exactly as before until an operator turns it on).
const settingAgentEgressLockdown = "agent_egress_lockdown"

const egressLockdownScript = "/app/deploy/egress-lockdown.sh"

// egressScriptTimeout bounds the rules script: it manipulates netfilter, which has
// been seen to block while the container is still starting.
const egressScriptTimeout = 30 * time.Second

// agentUIDs hands every task its own uid and remembers the mapping both ways:
// the shell wrapper needs uid-by-task, the listener needs task-by-uid.
type agentUIDs struct {
	mu     sync.Mutex
	next   int
	byTask map[string]int
	byUID  map[int]string
}

func newAgentUIDs() *agentUIDs {
	return &agentUIDs{next: agentUIDBase, byTask: map[string]int{}, byUID: map[int]string{}}
}

// UIDForTask returns the task's uid, allocating one on first use. A task keeps
// its uid for its whole lifetime, so processes started earlier still map back to
// it.
func (a *agentUIDs) UIDForTask(taskID string) int {
	taskID = strings.TrimSpace(taskID)
	if taskID == "" {
		return agentUID
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if uid, ok := a.byTask[taskID]; ok {
		return uid
	}
	uid := a.next
	if uid > agentUIDMax {
		uid = agentUIDBase
	}
	for {
		if _, taken := a.byUID[uid]; !taken {
			break
		}
		uid++
		if uid > agentUIDMax {
			uid = agentUIDBase
		}
	}
	a.next = uid + 1
	a.byTask[taskID] = uid
	a.byUID[uid] = taskID
	return uid
}

// TaskForUID is the reverse lookup the listener performs (SO_PEERCRED -> task).
func (a *agentUIDs) TaskForUID(uid int) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.byUID[uid]
}

// Release frees a task's uid.
func (a *agentUIDs) Release(taskID string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if uid, ok := a.byTask[taskID]; ok {
		delete(a.byTask, taskID)
		delete(a.byUID, uid)
	}
}

// Snapshot copies the task → uid map for display.
func (a *agentUIDs) Snapshot() map[string]int {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make(map[string]int, len(a.byTask))
	for k, v := range a.byTask {
		out[k] = v
	}
	return out
}

// UIDRange is the uid span the kernel rules match, as "lo-hi".
func (a *agentUIDs) UIDRange() string {
	return fmt.Sprintf("%d-%d", agentUIDBase, agentUIDMax)
}

// warmAgentUIDs pre-allocates the uid → task mapping and registers each task's
// identity. The rules cover the whole uid range already, but 「uid → task」 only
// holds once allocated: without it the first transparent connection after a restart
// carries an identity that resolves to task_id 0.
func (m *Manager) warmAgentUIDs() {
	if m.pg == nil || m.agentUIDs == nil {
		return
	}
	tasks, err := m.pg.ListTasks()
	if err != nil {
		return
	}
	for _, tk := range tasks {
		if tk == nil {
			continue
		}
		id := strconv.FormatInt(tk.ID, 10)
		m.AgentUIDForTask(id)
		m.TaskProxyAddrs(id)
	}
}

// ApplyEgressLockdownOnBoot makes a persisted 「on」 survive a restart. Without it
// the setting would advertise a confinement that is not in force — fail-open, the
// exact opposite of the intent.
//
// It refuses to confine the agent to a listener that is not running: with capture
// off every command would fail with a reset and nothing would be recorded, so the
// rules are left off and the reason is reported instead.
func (m *Manager) ApplyEgressLockdownOnBoot() {
	// Runs in the background on purpose. iptables has been observed to block while
	// the container is still coming up (netfilter not ready), and doing this inline
	// froze startup before the API ever listened — the published port accepted and
	// then reset every connection. Startup must never wait on an external command.
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[egress] 启动应用收敛时 panic（已忽略，不影响服务）: %v", r)
			}
		}()
		m.applyEgressLockdownOnBoot()
	}()
}

func (m *Manager) applyEgressLockdownOnBoot() {
	if m.agentUIDs == nil {
		m.agentUIDs = newAgentUIDs()
	}
	if !m.EgressLockdownEnabled() {
		m.setEgressRules("关闭")
		return
	}
	if !m.TrafficEnabled() || m.ProxyAddr() == "" {
		log.Printf("[egress] 设置里收敛是开启的，但监听器未运行 ⇒ 暂不应用规则（否则每条命令都会被重置）")
		m.setEgressRules("未生效：监听器未运行")
		return
	}
	if err := m.runEgressLockdown("apply"); err != nil {
		log.Printf("[egress] 启动时应用出网收敛失败（设置仍为开启，但规则未生效）: %v", err)
		m.setEgressRules("未生效：" + err.Error())
		return
	}
	m.warmAgentUIDs()
	log.Printf("[egress] 已应用出网收敛（uid %d + 每任务 %s）", agentUID, m.agentUIDs.UIDRange())
	m.setEgressRules("已生效")
}

// SuspendEgressRules removes the kernel rules WITHOUT changing the setting, for the
// case where the confinement must not be in force even though it is enabled: with
// capture off the listener is down, and a redirected agent would have every command
// reset instead of recorded. The setting stays on so re-enabling capture restores it.
func (m *Manager) SuspendEgressRules(reason string) {
	if err := m.runEgressLockdown("remove"); err != nil {
		log.Printf("[egress] 暂停出网收敛规则失败（%s）: %v", reason, err)
		m.setEgressRules("未生效：" + err.Error())
		return
	}
	log.Printf("[egress] 已暂停出网收敛规则：%s", reason)
	m.setEgressRules("未生效：" + reason)
}

// setEgressRules records what the kernel actually holds, so the settings page can
// never show 「on」 next to rules that are absent.
func (m *Manager) setEgressRules(s string) {
	m.egressMu.Lock()
	m.egressRules = s
	m.egressMu.Unlock()
}

// EgressRulesState is the human-readable state of the kernel rules.
func (m *Manager) EgressRulesState() string {
	m.egressMu.Lock()
	defer m.egressMu.Unlock()
	if m.egressRules == "" {
		return "未知"
	}
	return m.egressRules
}

// EgressLockdownEnabled reports whether the agent's traffic is confined to the
// listener by the kernel.
func (m *Manager) EgressLockdownEnabled() bool {
	if m.pg == nil {
		return false
	}
	return m.pg.GetBool(settingAgentEgressLockdown, false)
}

// AgentUIDForTask exposes the task -> uid mapping.
func (m *Manager) AgentUIDForTask(taskID string) int {
	if m.agentUIDs == nil {
		return agentUID
	}
	return m.agentUIDs.UIDForTask(taskID)
}

// TaskIDForAgentUID exposes the uid -> task mapping, used by the transparent
// ingress to attribute a connection that arrived without any client handshake.
func (m *Manager) TaskIDForAgentUID(uid int) string {
	if m.agentUIDs == nil {
		return ""
	}
	return m.agentUIDs.TaskForUID(uid)
}

// ReleaseAgentUID frees a task's uid when its runtime goes away.
func (m *Manager) ReleaseAgentUID(taskID string) {
	if m.agentUIDs != nil {
		m.agentUIDs.Release(taskID)
	}
}

// ApplyEgressLockdown turns the kernel rules on or off and persists the choice.
// A failure to apply (no CAP_NET_ADMIN, iptables missing) is returned to the
// caller and leaves the toggle off, so the UI never claims a confinement that is
// not in force.
func (m *Manager) ApplyEgressLockdown(on bool) error {
	if m.pg == nil {
		return fmt.Errorf("设置存储未启用")
	}
	action := "remove"
	if on {
		action = "apply"
	}
	if err := m.runEgressLockdown(action); err != nil {
		return err
	}
	if err := m.pg.SetBool(settingAgentEgressLockdown, on); err != nil {
		return err
	}
	if on {
		m.warmAgentUIDs()
	}
	if on {
		m.setEgressRules("已生效")
	} else {
		m.setEgressRules("关闭")
	}
	log.Printf("[egress] agent 出网收敛已%s（uid %d + 每任务 %s）",
		map[bool]string{true: "开启", false: "关闭"}[on], agentUID, m.agentUIDs.UIDRange())
	return nil
}

// AgentUIDMap 返回任务 → uid 的快照，供设置页展示/排障（哪个 uid 是哪个任务）。
func (m *Manager) AgentUIDMap() map[string]int {
	if m.agentUIDs == nil {
		return nil
	}
	return m.agentUIDs.Snapshot()
}

// EgressLockdownStatus returns the script's own view of the rules, for the
// settings page to show what is actually in force.
func (m *Manager) EgressLockdownStatus() string {
	out, err := m.runEgressLockdownOutput("status")
	if err != nil {
		return "不可用：" + err.Error()
	}
	return strings.TrimSpace(out)
}

// AgentShellEnv is the task-less variant (the chat agent).
func (m *Manager) AgentShellEnv() []string { return m.AgentShellEnvForTask("") }

// AgentShellEnvForTask is what a task's BashEnv needs for the shell wrapper to
// drop privileges into that task's uid. Empty when the lockdown is off, which
// leaves the wrapper inert.
func (m *Manager) AgentShellEnvForTask(taskID string) []string {
	if !m.EgressLockdownEnabled() {
		return nil
	}
	return []string{fmt.Sprintf("ARTEX_AGENT_UID=%d", m.AgentUIDForTask(taskID))}
}

func (m *Manager) runEgressLockdown(action string) error {
	out, err := m.runEgressLockdownOutput(action)
	if err != nil {
		return fmt.Errorf("规则%s失败：%v（%s）", action, err, strings.TrimSpace(out))
	}
	return nil
}

func (m *Manager) runEgressLockdownOutput(action string) (string, error) {
	if _, err := os.Stat(egressLockdownScript); err != nil {
		return "", fmt.Errorf("缺少 %s", egressLockdownScript)
	}
	env := append(os.Environ(),
		fmt.Sprintf("ARTEX_AGENT_UID=%d", agentUID),
		fmt.Sprintf("ARTEX_AGENT_UID_RANGE=%s", m.agentUIDs.UIDRange()),
	)
	ctx, cancel := context.WithTimeout(context.Background(), egressScriptTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, egressLockdownScript, action)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if ctxErr := ctx.Err(); ctxErr != nil {
		return string(out), fmt.Errorf("规则脚本超时（%s）: %w", egressScriptTimeout, ctxErr)
	}
	return string(out), err
}
