"use client";

// 平台文件管理：data/files 里的一切。
//
// 与「内网隧道」页的关系：平台生成的隧道载荷只是这份目录上的一个视图；这一页管的是
// 文件本身 —— 你可以上传自己的工具/字典/证书/脚本，也可以**替换**平台生成的载荷
// （替换后记为 override，重启/ Sync 都不会被还原）。
//
// 每个文件都可以带一句「说明」：文件库是给 agent 用的，而 agent 只看文件名并不知道
// suo5.php / next_payload.http 是什么、怎么用。说明会写进 manifest.json 一起交给它。

import { Fragment, useCallback, useEffect, useMemo, useState } from "react";
import { toast } from "sonner";

import { api } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";

interface FileEntry {
  name: string;
  size: number;
  mod_time: string;
  sha256?: string;
  payload: boolean;
  override?: boolean;
  description?: string;
  kind?: string;
  backend?: string;
  deploy?: string;
  target?: string;
  requires?: string;
  tunnel_url?: string;
  notes?: string[];
  caveats?: string[];
}

interface FileListResp {
  dir: string;
  files: FileEntry[];
  payload_count: number;
  total: number;
}

function fmtSize(n: number) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}

function fmtTime(s?: string) {
  if (!s) return "-";
  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? s : d.toLocaleString();
}

// 只有"自有文件"和"已替换的平台载荷"可以删/批量删；平台原版只能被替换，不能被删。
function isDeletable(f: FileEntry) {
  return !f.payload || Boolean(f.override);
}

export default function FilesPage() {
  const [data, setData] = useState<FileListResp | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [selected, setSelected] = useState<Set<string>>(() => new Set());
  const [open, setOpen] = useState<string | null>(null); // 展开看载荷说明

  // 上传弹窗
  const [upOpen, setUpOpen] = useState(false);
  const [upFiles, setUpFiles] = useState<File[]>([]);
  const [upDesc, setUpDesc] = useState("");

  // 编辑说明
  const [metaFor, setMetaFor] = useState<FileEntry | null>(null);
  const [metaText, setMetaText] = useState("");

  // 删除确认（单个或批量共用）
  const [pending, setPending] = useState<string[] | null>(null);

  const load = useCallback(async () => {
    try {
      const r = await api.files();
      setData(r);
      setErr(null);
      setSelected((prev) => new Set([...prev].filter((n) => r.files.some((f) => f.name === n))));
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const files = data?.files ?? [];
  const stats = useMemo(() => {
    const replaced = files.filter((f) => f.override).length;
    return { total: files.length, payload: files.filter((f) => f.payload).length, replaced, mine: files.filter((f) => !f.payload).length };
  }, [files]);
  const selectedFiles = files.filter((f) => selected.has(f.name));
  const deletableSelected = selectedFiles.filter(isDeletable);

  const toggle = (name: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  };
  const allChecked = files.length > 0 && selected.size === files.length;

  const doUpload = async () => {
    if (upFiles.length === 0) {
      toast.error("先选一个文件");
      return;
    }
    setBusy(true);
    try {
      const r = await api.fileUpload(upFiles, upDesc.trim());
      toast.success(`已上传 ${r.count} 个文件`);
      setUpOpen(false);
      setUpFiles([]);
      setUpDesc("");
      await load();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const doSaveMeta = async () => {
    if (!metaFor) return;
    setBusy(true);
    try {
      await api.fileMeta(metaFor.name, metaText.trim());
      toast.success("说明已保存");
      setMetaFor(null);
      await load();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const doDelete = async () => {
    if (!pending || pending.length === 0) return;
    setBusy(true);
    let ok = 0;
    try {
      for (const name of pending) {
        await api.fileDelete(name);
        ok++;
      }
      toast.success(`已删除 ${ok} 个文件`);
      setPending(null);
      await load();
    } catch (e) {
      toast.error(`删到第 ${ok + 1} 个失败：${e instanceof Error ? e.message : String(e)}`);
      await load();
    } finally {
      setBusy(false);
    }
  };

  const doRevert = async (f: FileEntry) => {
    if (!window.confirm(`用平台原版覆盖 ${f.name}？你的替换版本会被删除。`)) return;
    setBusy(true);
    try {
      await api.fileRevert(f.name);
      toast.success(`${f.name} 已恢复为平台版本`);
      await load();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="mx-auto flex max-w-6xl flex-col gap-4 p-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">文件管理</h1>
          <p className="text-muted-foreground mt-1 text-xs">
            agent 可调用的文件都在这里：自建载荷、工具、字典、证书、脚本。每个文件都可以写一句「说明」，
            它会写进 <span className="font-mono">manifest.json</span> 一起交给 agent —— 否则它只看文件名
            并不知道这是什么、怎么用。平台生成的载荷可以**直接上传同名文件替换**（记为「已替换」，重启不会被还原）。
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => void load()} disabled={busy}>
            刷新
          </Button>
          <Button size="sm" onClick={() => setUpOpen(true)} disabled={busy}>
            上传文件
          </Button>
        </div>
      </div>

      <div className="text-muted-foreground flex flex-wrap items-center gap-x-5 gap-y-1 text-xs">
        <span>
          文件 <span className="text-foreground font-medium">{stats.total}</span>
        </span>
        <span>
          隧道载荷 <span className="text-foreground font-medium">{stats.payload}</span>
        </span>
        <span>
          已替换 <span className="text-foreground font-medium">{stats.replaced}</span>
        </span>
        <span>
          自有文件 <span className="text-foreground font-medium">{stats.mine}</span>
        </span>
        <span className="font-mono">{data?.dir ?? "-"}</span>
      </div>

      {err ? <div className="rounded-md border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-700">{err}</div> : null}

      {/* 选中后才出现的操作条：与资产页一致，选中就有反馈 */}
      <div className="flex min-h-9 flex-wrap items-center gap-2">
        {selected.size > 0 ? (
          <>
            <span className="text-sm">
              已选 <span className="font-medium">{selected.size}</span> 个
            </span>
            <Button
              variant="outline"
              size="sm"
              disabled={busy || deletableSelected.length === 0}
              onClick={() => setPending(deletableSelected.map((f) => f.name))}
            >
              删除选中{deletableSelected.length !== selected.size ? `（可删 ${deletableSelected.length}）` : ""}
            </Button>
            <Button variant="ghost" size="sm" disabled={busy} onClick={() => setSelected(new Set())}>
              清除选择
            </Button>
          </>
        ) : (
          <span className="text-muted-foreground text-xs">勾选文件后可批量删除；平台原版载荷只能替换、不能删。</span>
        )}
      </div>

      <section className="rounded-lg border">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-muted/40 text-left">
              <tr>
                <th className="w-10 px-3 py-2">
                  <Checkbox
                    checked={allChecked}
                    onCheckedChange={() =>
                      setSelected(allChecked ? new Set() : new Set(files.map((f) => f.name)))
                    }
                  />
                </th>
                <th className="px-3 py-2">文件</th>
                <th className="px-3 py-2">类型</th>
                <th className="px-3 py-2">说明</th>
                <th className="px-3 py-2">大小</th>
                <th className="px-3 py-2">修改时间</th>
                <th className="px-3 py-2">操作</th>
              </tr>
            </thead>
            <tbody>
              {files.length === 0 ? (
                <tr>
                  <td className="text-muted-foreground px-3 py-8 text-center text-xs" colSpan={7}>
                    还没有文件。点右上角「上传文件」加一个。
                  </td>
                </tr>
              ) : null}
              {files.map((f) => (
                <Fragment key={f.name}>
                  <tr className={`border-t ${selected.has(f.name) ? "bg-muted/40" : ""}`}>
                    <td className="px-3 py-2">
                      <Checkbox checked={selected.has(f.name)} onCheckedChange={() => toggle(f.name)} />
                    </td>
                    <td className="px-3 py-2 font-mono text-xs">{f.name}</td>
                    <td className="px-3 py-2">
                      <div className="flex flex-wrap items-center gap-1">
                        {f.payload ? <Badge variant="secondary">载荷 · {f.kind}</Badge> : <Badge variant="outline">自有文件</Badge>}
                        {f.override ? <Badge className="bg-amber-100 text-amber-800">已替换</Badge> : null}
                      </div>
                    </td>
                    <td className="max-w-[22rem] px-3 py-2 text-xs">
                      {f.description ? (
                        <span className="line-clamp-2" title={f.description}>
                          {f.description}
                        </span>
                      ) : (
                        <span className="text-muted-foreground">（未填写）</span>
                      )}
                    </td>
                    <td className="px-3 py-2 text-xs">{fmtSize(f.size)}</td>
                    <td className="px-3 py-2 text-xs">{fmtTime(f.mod_time)}</td>
                    <td className="px-3 py-2 whitespace-nowrap">
                      <Button
                        variant="link"
                        size="sm"
                        className="h-6 px-1 text-xs"
                        onClick={() => {
                          setMetaFor(f);
                          setMetaText(f.description ?? "");
                        }}
                      >
                        说明
                      </Button>
                      <a
                        className="px-1 text-xs underline"
                        href={`/api/files/download?name=${encodeURIComponent(f.name)}`}
                      >
                        下载
                      </a>
                      {f.payload ? (
                        <>
                          <Button
                            variant="link"
                            size="sm"
                            className="h-6 px-1 text-xs"
                            onClick={() => setOpen(open === f.name ? null : f.name)}
                          >
                            {open === f.name ? "收起" : "详情"}
                          </Button>
                          {f.override ? (
                            <Button
                              variant="link"
                              size="sm"
                              className="h-6 px-1 text-xs"
                              disabled={busy}
                              onClick={() => void doRevert(f)}
                            >
                              恢复平台版本
                            </Button>
                          ) : null}
                        </>
                      ) : null}
                      {isDeletable(f) ? (
                        <Button
                          variant="link"
                          size="sm"
                          className="text-destructive h-6 px-1 text-xs"
                          disabled={busy}
                          onClick={() => setPending([f.name])}
                        >
                          删除
                        </Button>
                      ) : null}
                    </td>
                  </tr>
                  {open === f.name ? (
                    <tr className="bg-muted/20 border-t">
                      <td className="px-3 py-2 text-xs" colSpan={7}>
                        <dl className="grid grid-cols-[6rem_1fr] gap-x-3 gap-y-1">
                          {f.payload ? (
                            <>
                              <dt className="text-muted-foreground">后端</dt>
                              <dd>{f.backend || "-"}</dd>
                              <dt className="text-muted-foreground">投放方式</dt>
                              <dd className="font-mono">{f.deploy || "-"}</dd>
                              <dt className="text-muted-foreground">适用目标</dt>
                              <dd>{f.target || "-"}</dd>
                              <dt className="text-muted-foreground">要求</dt>
                              <dd>{f.requires || "-"}</dd>
                              <dt className="text-muted-foreground">隧道 URL</dt>
                              <dd className="font-mono">{f.tunnel_url || "-"}</dd>
                            </>
                          ) : null}
                          <dt className="text-muted-foreground">sha256</dt>
                          <dd className="font-mono">{f.sha256 || "（文件较大，未计算）"}</dd>
                        </dl>
                        {f.notes?.length ? (
                          <ul className="mt-2 list-disc pl-5">
                            {f.notes.map((n) => (
                              <li key={n}>{n}</li>
                            ))}
                          </ul>
                        ) : null}
                        {f.caveats?.length ? (
                          <ul className="mt-2 list-disc pl-5 text-amber-700">
                            {f.caveats.map((c) => (
                              <li key={c}>{c}</li>
                            ))}
                          </ul>
                        ) : null}
                      </td>
                    </tr>
                  ) : null}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* 上传：文件 + 说明一起交 */}
      <Dialog open={upOpen} onOpenChange={(v) => !busy && setUpOpen(v)}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>上传文件</DialogTitle>
            <DialogDescription>
              同名上传会**替换**已有文件；如果替换的是平台生成的载荷，会记为「已替换」且不会被还原。
            </DialogDescription>
          </DialogHeader>
          <div className="flex flex-col gap-3">
            <Input
              type="file"
              multiple
              onChange={(e) => setUpFiles(Array.from(e.target.files ?? []))}
              disabled={busy}
            />
            {upFiles.length > 0 ? (
              <div className="text-muted-foreground text-xs">
                将上传：{upFiles.map((f) => f.name).join("、")}
              </div>
            ) : null}
            <div className="flex flex-col gap-1">
              <label className="text-xs font-medium" htmlFor="file-desc">
                说明（这是什么、怎么用 —— 会写进 manifest.json 给 agent 看）
              </label>
              <Textarea
                id="file-desc"
                rows={3}
                placeholder="例：内网信息收集脚本，用法 python3 collect.py --cidr 10.0.0.0/24；或：我自建的隧道载荷，替代官方版本"
                value={upDesc}
                onChange={(e) => setUpDesc(e.target.value)}
                disabled={busy}
              />
            </div>
          </div>
          <DialogFooter>
            <DialogClose asChild>
              <Button variant="outline" size="sm" disabled={busy}>
                取消
              </Button>
            </DialogClose>
            <Button size="sm" disabled={busy || upFiles.length === 0} onClick={() => void doUpload()}>
              {busy ? "上传中…" : "上传"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* 编辑说明 */}
      <Dialog open={metaFor !== null} onOpenChange={(v) => !busy && !v && setMetaFor(null)}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>说明 · {metaFor?.name}</DialogTitle>
            <DialogDescription>agent 读 manifest.json 时会看到这句话。</DialogDescription>
          </DialogHeader>
          <Textarea
            rows={4}
            value={metaText}
            onChange={(e) => setMetaText(e.target.value)}
            placeholder="这是什么、怎么用、有什么前提"
            disabled={busy}
          />
          <DialogFooter>
            <DialogClose asChild>
              <Button variant="outline" size="sm" disabled={busy}>
                取消
              </Button>
            </DialogClose>
            <Button size="sm" disabled={busy} onClick={() => void doSaveMeta()}>
              {busy ? "保存中…" : "保存"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* 删除确认（单个/批量共用） */}
      <Dialog open={pending !== null} onOpenChange={(v) => !busy && !v && setPending(null)}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>删除文件</DialogTitle>
            <DialogDescription>
              将删除 {pending?.length ?? 0} 个文件，不可撤销。平台原版载荷不会被删（要换请上传同名文件）。
            </DialogDescription>
          </DialogHeader>
          <div className="max-h-40 overflow-auto font-mono text-xs">
            {(pending ?? []).map((n) => (
              <div key={n}>{n}</div>
            ))}
          </div>
          <DialogFooter>
            <DialogClose asChild>
              <Button variant="outline" size="sm" disabled={busy}>
                取消
              </Button>
            </DialogClose>
            <Button variant="destructive" size="sm" disabled={busy} onClick={() => void doDelete()}>
              {busy ? "删除中…" : "确认删除"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
