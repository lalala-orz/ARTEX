"use client";

// 内网隧道：在册隧道（含健康）、建立/关闭，以及任务出网环境查看。
//
// 数据全部来自实时接口（隧道活在进程里，重启即失效）。载荷文件在「文件管理」页：
// 这里只负责把载荷 URL 与任务绑成一条隧道。

import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";

import { api, http } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";

interface TunnelInfo {
  id: string;
  task_id: number;
  server_url: string;
  egress: string;
  probe: string;
  opened_at: string;
  healthy: boolean;
  reason?: string;
  probed_at?: string;
}

interface PendingEgress {
  task_id: number;
  url: string;
  probe?: string;
  reason?: string;
  at: string;
  last_try?: string;
}

interface TunnelListResp {
  tunnels: TunnelInfo[];
  // 还没生效的出口意图（建任务时填的、或绑定失败过）：也渲染出来并给「重试绑定」。
  pending?: PendingEgress[];
  payload_dir: string;
}

function fmtTime(s?: string) {
  if (!s) return "-";
  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? s : d.toLocaleString();
}

export default function TunnelsPage() {
  const [list, setList] = useState<TunnelListResp | null>(null);
  const [pending, setPending] = useState<PendingEgress[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // 非空表示"正在给这个任务换隧道"：上面的表单会切成替换模式（旧隧道在新建成功后关闭）。
  const [replaceTask, setReplaceTask] = useState("");

  // 任务下拉（建隧道 / 查环境共用）
  const [taskOpts, setTaskOpts] = useState<{ id: string; label: string; status: string }[]>([]);
  // 任务列表本身失败也要说出来（否则下拉空着，用户以为没这个功能）。
  const [taskErr, setTaskErr] = useState<string | null>(null);
  const [task, setTask] = useState("");

  // 建隧道表单
  const [url, setUrl] = useState("");
  const [probe, setProbe] = useState("");
  const [backend, setBackend] = useState("regeorg");
  // 绑定方式：投放载荷（平台内置 regeorg 客户端）或"我已有的隧道/代理"（直拨，不经 global_proxy）。
  const [bindMode, setBindMode] = useState<"payload" | "proxy">("payload");
  // 上游（控制通道出口）：""=跟随 global_proxy；direct=直连载荷；其它=代理 URL
  const [upstream, setUpstream] = useState("");

  const [urlHints, setUrlHints] = useState<string[]>([]);

  const refresh = useCallback(async () => {
    try {
      const t = await http<TunnelListResp>("/tunnels");
      setList(t);
      setPending(t.pending ?? []);
      setErr(null);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  }, []);

  useEffect(() => {
    void refresh();
    const timer = setInterval(() => void refresh(), 5000);
    return () => clearInterval(timer);
  }, [refresh]);

  // 任务下拉 + 文件库里的载荷 URL 联想
  useEffect(() => {
    loadTasks();
    api
      .files()
      .then((r) => {
        setUrlHints(
          (r.files ?? [])
            .filter((f) => f.tunnel_url)
            .map((f) => f.tunnel_url as string),
        );
      })
      .catch(() => undefined);
  }, []);

  // 任务列表：失败必须说出来 —— 以前这里静默吞掉异常，于是下拉空着、按钮一直灰着、
  // 界面上什么都不说，看起来就像"前端没做这个功能"。
  function loadTasks() {
    setTaskErr(null);
    api
      .tasks()
      .then((r) => {
        const opts = (r.tasks ?? []).map((t) => ({
          id: t.id,
          label: (t.description || t.name || "").slice(0, 40),
          status: t.status ?? "",
        }));
        setTaskOpts(opts);
        if (opts.length > 0) {
          setTask((prev) => prev || opts[0].id);
        }
      })
      .catch((e) => setTaskErr(`任务列表加载失败：${e instanceof Error ? e.message : String(e)}`));
  }

  async function createTunnel() {
    setBusy(true);
    setErr(null);
    try {
      const payload = {
        kind: bindMode === "proxy" ? "proxy" : "regeorg",
        url: url.trim(),
        probe: probe.trim(),
        // 代理型没有控制通道：upstream 无关，明确不传。
        upstream: bindMode === "proxy" ? "" : upstream,
      };
      if (replaceTask) {
        const r = await api.replaceTunnel(replaceTask, payload);
        toast.success(`已替换 #${replaceTask} 的隧道（旧 ${r.replaced} 条已关闭）：${r.egress}`);
        setReplaceTask("");
      } else {
        await http<TunnelListResp>(`/tasks/${encodeURIComponent(task.trim())}/tunnel`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
        toast.success("隧道已建立并绑定到任务");
      }
      setUrl("");
      setProbe("");
      await refresh();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e));
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  // 重试绑定一个"还没生效"的出口：直接按存下来的地址再 POST 一次（成功后端会清掉待生效记录）。
  // 只测连通性、不绑定：先确认这条代理真能出去，再决定绑不绑。
  async function testConnectivity() {
    setBusy(true);
    try {
      const r = await api.tunnelProbe(url.trim(), probe.trim());
      if (r.ok) toast.success(`能上网：${r.site} → HTTP ${r.status}（${r.latency_ms ?? "-"} ms）`);
      else toast.error(`不通：${r.reason ?? "未知原因"}`);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  // 重探某条已绑隧道：不改绑定，只立刻要一个"现在还通不通"的答案。
  async function checkTunnel(t: TunnelInfo) {
    setBusy(true);
    try {
      const r = await api.tunnelCheck(t.task_id);
      if (r.healthy) toast.success(`#${t.task_id} 连通（${r.tunnels} 条隧道）`);
      else toast.error(`#${t.task_id} 不通：${r.reason || "未知原因"}`);
      await refresh();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }
  async function retryBind(p: PendingEgress) {
    setBusy(true);
    try {
      await http(`/tasks/${p.task_id}/tunnel`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: p.url, backend: "proxy", probe: p.probe ?? "", upstream: "" }),
      });
      toast.success("出口已生效");
      await refresh();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function closeTunnel(t: TunnelInfo) {
    if (!window.confirm(`关闭任务 ${t.task_id} 的隧道（${t.server_url}）？`)) return;
    setBusy(true);
    setErr(null);
    try {
      await http(`/tasks/${t.task_id}/tunnel`, { method: "DELETE" });
      toast.success("隧道已关闭");
      await refresh();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }


  const tunnels = list?.tunnels ?? [];
  const healthyCount = tunnels.filter((t) => t.healthy).length;
  const badCount = tunnels.length - healthyCount;

  return (
    <div className="flex flex-col gap-6 p-6">
      <div>
        <h1 className="font-semibold text-2xl">内网隧道</h1>
        <p className="text-muted-foreground mt-1 text-sm">
          挂了隧道，该任务的出网流量由它自己的隧道送出（不经{" "}
          <span className="font-mono">global_proxy</span>）；没挂隧道才轮到全局代理。
          隧道的控制通道（平台 → 载荷）默认跟随 <span className="font-mono">global_proxy</span>，
          <b>载荷在内网时请选「直连载荷」</b>。
        </p>
      </div>

      {err ? (
        <div className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm">{err}</div>
      ) : null}

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <StatCard label="在册隧道" value={String(tunnels.length)} />
        <StatCard label="健康" value={String(healthyCount)} tone="ok" />
        <StatCard label="不健康" value={String(badCount)} tone={badCount > 0 ? "bad" : undefined} />
        <StatCard label="文件库" value={list?.payload_dir ?? "-"} mono small />
      </div>

      <section className="rounded-lg border p-4">
        <h2 className="font-medium">建立隧道</h2>
        {taskErr ? (
          <div className="mt-2 rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs">
            {taskErr}
          </div>
        ) : null}
        <p className="text-muted-foreground mt-1 text-xs">
          {bindMode === "proxy" ? (
            <>
              把<b>你已有的隧道/代理</b>绑给这个任务当出口：平台直拨它，<b>不经过 global_proxy</b>。
              这类绑定没有控制通道（平台不去投放任何载荷）。探活目标留空默认 <span className="font-mono">1.1.1.1:80</span>；
              专供内网的代理连不上它，请显式填一个"从代理那侧能连到"的地址。
            </>
          ) : (
            <>
          绑定前会经隧道<b>端到端探活</b>一次（建议填只有目标自己能连的地址，如 127.0.0.1:80）；
          探活不过会拒绝绑定，任务继续走原出口 —— 宁可失败，也不让流量悄悄绕过跳板。
            </>
          )}
        </p>
        <div className="mt-3 grid gap-3 md:grid-cols-2">
          <div className="flex flex-col gap-1.5">
            <Label className="text-xs">任务</Label>
            <Select value={task} onValueChange={setTask}>
              <SelectTrigger size="sm" className="w-full">
                <SelectValue placeholder="选择任务" />
              </SelectTrigger>
              <SelectContent>
                {taskOpts.map((t) => (
                  <SelectItem key={t.id} value={t.id}>
                    #{t.id} {t.label}
                    {t.status ? ` · ${t.status}` : ""}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="flex flex-col gap-1.5">
            <Label className="text-xs">绑定方式</Label>
            <Select value={bindMode} onValueChange={(v) => setBindMode(v as "payload" | "proxy")}>
              <SelectTrigger size="sm" className="w-full">
                <SelectValue placeholder="绑定方式" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="payload">投放载荷（Neo-ReGeorg）</SelectItem>
                <SelectItem value="proxy">我已有的隧道/代理（socks5 / http）</SelectItem>
              </SelectContent>
            </Select>
          </div>
          {bindMode === "payload" ? (
            <div className="flex flex-col gap-1.5">
              <Label className="text-xs">后端</Label>
              <Select value={backend} onValueChange={setBackend}>
                <SelectTrigger size="sm" className="w-full">
                  <SelectValue placeholder="后端" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="regeorg">regeorg（Neo-ReGeorg）</SelectItem>
                </SelectContent>
              </Select>
            </div>
          ) : null}
          <div className="flex flex-col gap-1.5 md:col-span-2">
            <Label className="text-xs">{bindMode === "proxy" ? "代理地址（socks5://user:pass@host:port 或 http://host:port）" : "载荷 URL"}</Label>
            <Input
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder={bindMode === "proxy" ? "socks5://127.0.0.1:1080（你已有的隧道入口）" : "http://目标/tunnel.php（文件管理里上传的载荷，访问路径填这里）"}
              list="tunnel-url-hints"
            />
            <datalist id="tunnel-url-hints">
              {urlHints.map((h) => (
                <option key={h} value={h} />
              ))}
            </datalist>
          </div>
          {bindMode === "payload" ? (
            <div className="flex flex-col gap-1.5">
              <Label className="text-xs">控制通道出口（upstream）</Label>
              <Select value={upstream || "follow"} onValueChange={(v) => setUpstream(v === "follow" ? "" : v)}>
                <SelectTrigger size="sm" className="w-full">
                  <SelectValue placeholder="跟随 global_proxy" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="follow">跟随 global_proxy（默认）</SelectItem>
                  <SelectItem value="direct">直连载荷（载荷在私网/内网时必选）</SelectItem>
                </SelectContent>
              </Select>
            </div>
          ) : null}
          <div className="flex flex-col gap-1.5">
            <Label className="text-xs">测试网站 / 探活目标（可选）</Label>
            <Input value={probe} onChange={(e) => setProbe(e.target.value)} placeholder="127.0.0.1:80" />
          </div>
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-3">
          <Button size="sm" disabled={busy || !task || !url.trim()} onClick={() => void createTunnel()}>
            {busy ? "处理中…" : replaceTask ? "替换隧道" : "建立并绑定"}
          </Button>
          {replaceTask ? (
            <Button variant="ghost" size="sm" onClick={() => setReplaceTask("")}>
              取消替换
            </Button>
          ) : null}
          <Button variant="ghost" size="sm" onClick={() => loadTasks()}>
            刷新任务
          </Button>
          <Button
            variant="outline"
            size="sm"
            disabled={busy || !url.trim()}
            onClick={() => void testConnectivity()}
          >
            测试连通性
          </Button>
          <span className="text-muted-foreground text-xs">
            {taskErr
              ? taskErr
              : taskOpts.length === 0
                ? "没有可选任务：先在没有结束的任务里选一个（已结束的任务平台不允许新建出口）。"
                : !task
                  ? "请选择任务。"
                  : !url.trim()
                    ? "请填写地址（载荷 URL 或 socks5/http 代理地址）。"
                    : ""}
          </span>
        </div>
      </section>

      <section className="rounded-lg border">
        <div className="flex items-center justify-between border-b px-4 py-2">
          <h2 className="font-medium">在册隧道</h2>
          <Button variant="ghost" size="sm" onClick={() => void refresh()}>
            刷新
          </Button>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-muted/40 text-left">
              <tr>
                <th className="px-3 py-2">任务</th>
                <th className="px-3 py-2">出口地址</th>
                <th className="px-3 py-2">健康</th>
                <th className="px-3 py-2">最近探活</th>
                <th className="px-3 py-2">操作</th>
              </tr>
            </thead>
            <tbody>
              {tunnels.length === 0 ? (
                <tr>
                  <td className="text-muted-foreground px-3 py-6 text-center text-xs" colSpan={5}>
                    暂无隧道，也没有待生效的出口。上面选任务、填地址建一条（或新建任务时直接填出口）。
                  </td>
                </tr>
              ) : null}
              {tunnels.map((t) => (
                <tr key={t.id} className="border-t">
                  <td className="px-3 py-2 text-xs">#{t.task_id}</td>
                  <td className="px-3 py-2 font-mono text-xs">
                    <div className="flex items-center gap-1.5">
                      {t.egress?.startsWith("proxy:") ? (
                        <Badge variant="outline">已有代理</Badge>
                      ) : (
                        <Badge variant="secondary">载荷隧道</Badge>
                      )}
                      <span>{t.server_url}</span>
                    </div>
                  </td>
                  <td className="px-3 py-2">
                    {t.healthy ? (
                      <Badge className="bg-emerald-100 text-emerald-800">健康</Badge>
                    ) : (
                      <Badge variant="destructive">不健康</Badge>
                    )}
                    {t.reason ? <div className="text-muted-foreground mt-1 text-xs">{t.reason}</div> : null}
                  </td>
                  <td className="px-3 py-2 text-xs">{fmtTime(t.probed_at)}</td>
                  <td className="px-3 py-2">
                    <div className="flex items-center gap-2">
                      <Button
                        variant="outline"
                        size="sm"
                        className="h-7"
                        disabled={busy}
                        onClick={() => void checkTunnel(t)}
                      >
                        测连通性
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        className="h-7"
                        disabled={busy}
                        onClick={() => {
                          setReplaceTask(String(t.task_id));
                          setTask(String(t.task_id));
                          toast.info(`在下面填新隧道地址，点「替换隧道」即可换掉 #${t.task_id} 的这条`);
                        }}
                      >
                        更换
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        className="h-7"
                        disabled={busy}
                        onClick={() => void closeTunnel(t)}
                      >
                        关闭
                      </Button>
                    </div>
                  </td>
                </tr>
              ))}
              {pending.map((p) => (
                <tr key={`pending-${p.task_id}`} className="border-t">
                  <td className="px-3 py-2 text-xs">#{p.task_id}</td>
                  <td className="px-3 py-2 font-mono text-xs">{p.url}</td>
                  <td className="px-3 py-2">
                    <Badge className="bg-amber-100 text-amber-800">未生效</Badge>
                    {p.reason ? <div className="text-muted-foreground mt-1 text-xs">{p.reason}</div> : null}
                  </td>
                  <td className="px-3 py-2 text-xs">{p.last_try ?? p.at}</td>
                  <td className="px-3 py-2">
                    <Button
                      variant="outline"
                      size="sm"
                      className="h-7"
                      disabled={busy}
                      onClick={() => void retryBind(p)}
                    >
                      重试绑定
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

function StatCard({
  label,
  value,
  tone,
  mono,
  small,
}: {
  label: string;
  value: string;
  tone?: "ok" | "bad";
  mono?: boolean;
  small?: boolean;
}) {
  const valueClass = tone === "ok" ? "text-emerald-600" : tone === "bad" ? "text-red-600" : "text-foreground";
  return (
    <div className="rounded-lg border px-3 py-2">
      <div className="text-muted-foreground text-xs">{label}</div>
      <div className={`${valueClass} mt-0.5 font-medium ${mono ? "font-mono" : ""} ${small ? "truncate text-xs" : "text-lg"}`}>
        {value}
      </div>
    </div>
  );
}