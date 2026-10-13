"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { ScoredItem, SourceKind } from "@/lib/types";

const BASE = process.env.NEXT_PUBLIC_BASE_PATH || "";
const WATCH_KEY = "radar.watch";
const DAY = 24 * 3600 * 1000;

const TABS: { key: "all" | SourceKind; label: string }[] = [
  { key: "all", label: "全部" },
  { key: "kev", label: "在野利用 KEV" },
  { key: "cve", label: "高危 CVE" },
  { key: "ghsa", label: "GitHub Advisory" },
  { key: "cn", label: "中文漏洞库" },
  { key: "news", label: "安全资讯" },
];

const SRC_CLASS: Record<SourceKind, string> = {
  cve: "s-cve",
  ghsa: "s-ghsa",
  kev: "s-kev",
  cn: "s-cn",
  news: "s-news",
};

type FilterKey = "kev" | "poc" | "epss" | "ransom" | "fresh" | "watch";

const FILTERS: { key: FilterKey; label: string }[] = [
  { key: "kev", label: "在野利用" },
  { key: "poc", label: "有公开 PoC" },
  { key: "epss", label: "EPSS ≥ 10%" },
  { key: "ransom", label: "勒索相关" },
  { key: "fresh", label: "近 7 天" },
  { key: "watch", label: "只看关注" },
];

function ageDays(iso?: string) {
  const t = iso ? Date.parse(iso) : NaN;
  return Number.isNaN(t) ? Infinity : (Date.now() - t) / DAY;
}

function sevClass(it: ScoredItem): string {
  if (it.source === "news") return "sev-info";
  if (it.source === "kev") return it.ransomware ? "sev-crit" : "sev-high";
  const s = it.score ?? 0;
  if (s >= 9 || it.severity === "CRITICAL") return "sev-crit";
  return "sev-high";
}

function date(iso?: string) {
  if (!iso) return "";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return iso.slice(0, 10);
  return new Date(t).toLocaleDateString("zh-CN", { timeZone: "Asia/Shanghai" });
}

function pct(v?: number, digits = 0) {
  return v === undefined ? "" : `${(v * 100).toFixed(digits)}%`;
}

function displayTitle(it: ScoredItem) {
  if (it.title === it.id && it.summary) return `${it.id} — ${it.summary.slice(0, 90)}${it.summary.length > 90 ? "…" : ""}`;
  return it.title;
}

function matchesWatch(it: ScoredItem, words: string[]) {
  if (!words.length) return false;
  const hay = `${it.id} ${it.cve ?? ""} ${it.title} ${it.summary ?? ""} ${it.sourceName} ${(it.tags ?? []).join(" ")}`.toLowerCase();
  return words.some((w) => hay.includes(w));
}

function Badges({ it, watched }: { it: ScoredItem; watched: boolean }) {
  return (
    <>
      {watched && <span className="badge b-watch">★ 关注</span>}
      {it.epss !== undefined && (
        <span
          className={`badge b-epss ${it.epss >= 0.1 ? "hot" : ""}`}
          title={`EPSS：未来 30 天被利用概率 ${pct(it.epss, 2)}，高于 ${pct(it.epssPct, 1)} 的 CVE`}
        >
          EPSS {pct(it.epss, it.epss < 0.01 ? 2 : 0)}
        </span>
      )}
      {it.poc && (
        <span className="badge b-poc" title={`GitHub 上有 ${it.poc.count} 个公开 PoC 仓库，最高 ${it.poc.stars} star`}>
          PoC ×{it.poc.count}
        </span>
      )}
      {it.kevDueDays !== undefined && (
        <span
          className={`badge ${it.kevDueDays < 0 ? "b-overdue" : it.kevDueDays <= 7 ? "b-due" : "b-due-far"}`}
          title={`CISA 要求的修复截止日：${it.dueDate}`}
        >
          {it.kevDueDays < 0 ? `已逾期 ${-it.kevDueDays} 天` : `剩 ${it.kevDueDays} 天修复`}
        </span>
      )}
      {it.ransomware && <span className="badge b-ransom">勒索利用</span>}
      {it.seenIn.length > 1 && <span className="badge badge-multi">多源印证 ×{it.seenIn.length}</span>}
      {it.lang === "zh" && it.source === "news" && <span className="badge">中文</span>}
    </>
  );
}

function toCsv(rows: ScoredItem[]) {
  const head = ["来源", "编号", "CVE", "标题", "严重度/CVSS", "EPSS", "EPSS百分位", "公开PoC数", "KEV修复截止", "勒索利用", "优先级", "打分理由", "发布时间", "链接"];
  const esc = (v: unknown) => {
    const s = v === undefined || v === null ? "" : String(v);
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const lines = rows.map((i) =>
    [
      i.sourceName,
      i.id,
      i.cve ?? "",
      i.title,
      i.score ? i.score.toFixed(1) : i.severity ?? "",
      i.epss !== undefined ? i.epss.toFixed(4) : "",
      i.epssPct !== undefined ? i.epssPct.toFixed(4) : "",
      i.poc?.count ?? "",
      i.dueDate ?? "",
      i.ransomware ? "是" : "",
      i.priority,
      i.reasons.join("；"),
      i.publishedAt ?? "",
      i.url,
    ]
      .map(esc)
      .join(","),
  );
  return "﻿" + [head.join(","), ...lines].join("\n");
}

export default function IntelBoard({ items, top }: { items: ScoredItem[]; top: ScoredItem[] }) {
  const [tab, setTab] = useState<"all" | SourceKind>("all");
  const [q, setQ] = useState("");
  const [sort, setSort] = useState<"priority" | "time" | "epss">("priority");
  const [filters, setFilters] = useState<Set<FilterKey>>(new Set());
  const [watch, setWatch] = useState<string[]>([]);
  const [watchInput, setWatchInput] = useState("");
  const [active, setActive] = useState<ScoredItem | null>(null);
  const [copied, setCopied] = useState(false);

  // 关注清单：URL ?watch= 优先，其次本地存储
  useEffect(() => {
    const fromUrl = new URLSearchParams(window.location.search).get("watch");
    let initial: string[] = [];
    if (fromUrl) initial = fromUrl.split(",");
    else {
      try {
        initial = JSON.parse(window.localStorage.getItem(WATCH_KEY) || "[]");
      } catch {
        initial = [];
      }
    }
    setWatch(initial.map((w) => w.trim().toLowerCase()).filter(Boolean));
  }, []);

  const saveWatch = useCallback((next: string[]) => {
    setWatch(next);
    try {
      window.localStorage.setItem(WATCH_KEY, JSON.stringify(next));
    } catch {
      /* 隐私模式等情况下存储不可用，忽略 */
    }
  }, []);

  const addWatch = () => {
    const words = watchInput
      .split(/[,，\s]+/)
      .map((w) => w.trim().toLowerCase())
      .filter(Boolean);
    if (words.length) saveWatch([...new Set([...watch, ...words])]);
    setWatchInput("");
  };

  const shareWatch = async () => {
    const url = `${window.location.origin}${window.location.pathname}?watch=${encodeURIComponent(watch.join(","))}`;
    try {
      await navigator.clipboard.writeText(url);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      window.prompt("复制这个链接分享关注清单：", url);
    }
  };

  const toggleFilter = (k: FilterKey) =>
    setFilters((prev) => {
      const next = new Set(prev);
      if (next.has(k)) next.delete(k);
      else next.add(k);
      return next;
    });

  const counts = useMemo(() => {
    const c: Record<string, number> = { all: items.length };
    for (const i of items) c[i.source] = (c[i.source] ?? 0) + 1;
    return c;
  }, [items]);

  const shown = useMemo(() => {
    const kw = q.trim().toLowerCase();
    const pass = (i: ScoredItem) => {
      if (filters.has("kev") && !(i.source === "kev" || i.seenIn.includes("kev"))) return false;
      if (filters.has("poc") && !i.poc) return false;
      if (filters.has("epss") && (i.epss ?? 0) < 0.1) return false;
      if (filters.has("ransom") && !i.ransomware) return false;
      if (filters.has("fresh") && ageDays(i.publishedAt) > 7) return false;
      if (filters.has("watch") && !matchesWatch(i, watch)) return false;
      return true;
    };
    return items
      .filter((i) => tab === "all" || i.source === tab)
      .filter(pass)
      .filter(
        (i) =>
          !kw ||
          `${i.id} ${i.cve ?? ""} ${i.title} ${i.summary ?? ""} ${i.sourceName} ${(i.tags ?? []).join(" ")}`
            .toLowerCase()
            .includes(kw),
      )
      .sort((a, b) => {
        const wa = matchesWatch(a, watch) ? 1 : 0;
        const wb = matchesWatch(b, watch) ? 1 : 0;
        if (wa !== wb) return wb - wa;
        if (sort === "time") return (Date.parse(b.publishedAt ?? "") || 0) - (Date.parse(a.publishedAt ?? "") || 0);
        if (sort === "epss") return (b.epss ?? -1) - (a.epss ?? -1);
        return b.priority - a.priority;
      });
  }, [items, tab, q, sort, filters, watch]);

  const exportCsv = () => {
    const blob = new Blob([toCsv(shown)], { type: "text/csv;charset=utf-8" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `security-radar-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  return (
    <>
      {top.length > 0 && (
        <section className="panel top-panel">
          <h2 className="panel-title">🚨 优先处置 Top {top.length}</h2>
          <ol className="top-list">
            {top.map((t) => (
              <li key={`${t.source}-${t.id}`}>
                <div className="top-head">
                  <span className="prio" title="规则引擎优先级">
                    {t.priority}
                  </span>
                  <button className="top-title linklike" onClick={() => setActive(t)}>
                    {displayTitle(t)}
                  </button>
                </div>
                <div className="reasons">
                  {t.reasons.map((r) => (
                    <span key={r} className="reason">
                      {r}
                    </span>
                  ))}
                  {t.kevDueDays !== undefined && (
                    <span className={`reason ${t.kevDueDays < 0 ? "reason-bad" : ""}`}>
                      {t.kevDueDays < 0 ? `KEV 已逾期 ${-t.kevDueDays} 天` : `KEV 剩 ${t.kevDueDays} 天`}
                    </span>
                  )}
                </div>
              </li>
            ))}
          </ol>
        </section>
      )}

      <section className="board">
        <div className="toolbar">
          <div className="tabs">
            {TABS.map((t) => (
              <button key={t.key} className={`tab ${tab === t.key ? "active" : ""}`} onClick={() => setTab(t.key)}>
                {t.label} <span className="tab-n">{counts[t.key] ?? 0}</span>
              </button>
            ))}
          </div>
          <div className="controls">
            <input
              className="search"
              placeholder="搜索 CVE 编号 / 厂商 / 关键词"
              value={q}
              onChange={(e) => setQ(e.target.value)}
            />
            <select className="sort" value={sort} onChange={(e) => setSort(e.target.value as typeof sort)}>
              <option value="priority">按优先级</option>
              <option value="epss">按 EPSS</option>
              <option value="time">按时间</option>
            </select>
          </div>
        </div>

        <div className="filterbar">
          <div className="chips">
            {FILTERS.map((f) => (
              <button
                key={f.key}
                className={`chip ${filters.has(f.key) ? "on" : ""}`}
                onClick={() => toggleFilter(f.key)}
                disabled={f.key === "watch" && !watch.length}
              >
                {f.label}
              </button>
            ))}
          </div>
          <button className="chip export" onClick={exportCsv} title="导出当前筛选结果为 CSV">
            ⬇ 导出 CSV（{shown.length}）
          </button>
        </div>

        <div className="watchbar">
          <span className="watch-label">关注资产</span>
          {watch.map((w) => (
            <span key={w} className="wchip">
              {w}
              <button aria-label={`移除 ${w}`} onClick={() => saveWatch(watch.filter((x) => x !== w))}>
                ×
              </button>
            </span>
          ))}
          <input
            className="watch-input"
            placeholder={watch.length ? "继续添加…" : "输入厂商/产品，如 fortinet, gitlab，回车添加"}
            value={watchInput}
            onChange={(e) => setWatchInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && addWatch()}
          />
          {watch.length > 0 && (
            <button className="chip" onClick={shareWatch}>
              {copied ? "已复制链接" : "分享关注清单"}
            </button>
          )}
        </div>

        {shown.length === 0 ? (
          <div className="empty">没有匹配的情报，试试取消部分筛选条件</div>
        ) : (
          <div className="list">
            {shown.map((it) => {
              const watched = matchesWatch(it, watch);
              return (
                <article key={`${it.source}-${it.id}`} className={`item ${sevClass(it)} ${watched ? "watched" : ""}`}>
                  <div className="item-head">
                    <span className={`src ${SRC_CLASS[it.source]}`}>{it.sourceName}</span>
                    {it.score ? <span className="score">CVSS {it.score.toFixed(1)}</span> : null}
                    {it.severity && !it.score && it.source !== "kev" ? <span className="sev">{it.severity}</span> : null}
                    {it.source === "kev" ? <span className="sev">在野利用</span> : null}
                    <Badges it={it} watched={watched} />
                    <span className="when">{date(it.publishedAt)}</span>
                    <span className="prio-sm" title="规则引擎优先级">
                      P{it.priority}
                    </span>
                  </div>
                  <button className="item-title linklike" onClick={() => setActive(it)}>
                    {it.title}
                  </button>
                  {it.summary && it.summary !== it.title ? <p className="item-sum">{it.summary}</p> : null}
                  {it.tags && it.tags.length > 0 && (
                    <div className="badges">
                      {it.tags.map((t) => (
                        <span key={t} className="badge">
                          #{t}
                        </span>
                      ))}
                    </div>
                  )}
                </article>
              );
            })}
          </div>
        )}
      </section>

      {active && <CveDrawer item={active} items={items} onClose={() => setActive(null)} />}
    </>
  );
}

interface CveDetail {
  id: string;
  found: boolean;
  description?: string;
  published?: string;
  cvss?: { score?: number; severity?: string; vector?: string };
  cwes: { id: string; name: string }[];
  affected: { vendor?: string; product?: string; versions: string[] }[];
  references: { url: string; tags: string[] }[];
  ssvc?: { exploitation: string; automatable: string; technicalImpact: string; decision: string };
  kevDateAdded?: string;
  epss?: { epss: number; pct: number };
  poc?: { count: number; stars: number; top: { name: string; url: string; stars: number }[] } | null;
  errors: string[];
}

const DECISION: Record<string, { label: string; cls: string; text: string }> = {
  Act: { label: "立即处置（Act）", cls: "act", text: "已被在野利用，且可自动化利用或能完全控制系统，应立即修复或缓解。" },
  Attend: { label: "重点关注（Attend）", cls: "attend", text: "存在利用或利用条件较好，需尽快安排修复并加强监测。" },
  "Track*": { label: "密切跟踪（Track*）", cls: "track2", text: "已有 PoC 或影响较大，按常规周期修复，同时关注利用动态。" },
  Track: { label: "常规跟踪（Track）", cls: "track", text: "暂未见利用，按常规补丁周期处理即可。" },
};

const SSVC_TEXT: Record<string, string> = {
  none: "未见利用",
  poc: "有公开 PoC",
  active: "在野利用",
  yes: "可自动化利用",
  no: "难以自动化",
  partial: "部分控制",
  total: "完全控制",
};

const detailCache = new Map<string, CveDetail>();

function CveDrawer({ item, items, onClose }: { item: ScoredItem; items: ScoredItem[]; onClose: () => void }) {
  const cve = item.cve;
  const [detail, setDetail] = useState<CveDetail | null>(cve ? detailCache.get(cve) ?? null : null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const closeRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    closeRef.current?.focus();
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  useEffect(() => {
    if (!cve || detailCache.has(cve)) return;
    let alive = true;
    setLoading(true);
    setError("");
    fetch(`${BASE}/api/cve/${cve}`)
      .then((r) => r.json())
      .then((d: CveDetail) => {
        if (!alive) return;
        detailCache.set(cve, d);
        setDetail(d);
      })
      .catch((e) => alive && setError(String(e)))
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
  }, [cve]);

  // 同一 CVE 在长亭漏洞库里的中文修复建议
  const cnFix = item.fixSteps ?? items.find((i) => i.source === "cn" && i.cve && i.cve === cve && i.fixSteps)?.fixSteps;
  const related = cve ? items.filter((i) => i.cve === cve && i !== item) : [];
  const decision = detail?.ssvc ? DECISION[detail.ssvc.decision] : undefined;
  const epss = detail?.epss ?? (item.epss !== undefined ? { epss: item.epss, pct: item.epssPct ?? 0 } : undefined);
  const poc = detail?.poc ?? item.poc;

  return (
    <div className="drawer-overlay" onClick={onClose}>
      <aside className="drawer" role="dialog" aria-modal="true" aria-label={`${cve ?? item.id} 详情`} onClick={(e) => e.stopPropagation()}>
        <header className="d-head">
          <div>
            <div className="d-id">
              <span className={`src ${SRC_CLASS[item.source]}`}>{item.sourceName}</span> {cve ?? item.id}
            </div>
            <h3 className="d-title">{item.title}</h3>
          </div>
          <button ref={closeRef} className="d-close" onClick={onClose} aria-label="关闭">
            ×
          </button>
        </header>

        <div className="d-body">
          <div className="d-prio">
            <span className="prio">{item.priority}</span>
            <div className="reasons">
              {item.reasons.map((r) => (
                <span key={r} className="reason">
                  {r}
                </span>
              ))}
            </div>
          </div>

          {decision && detail?.ssvc && (
            <div className={`ssvc ${decision.cls}`}>
              <div className="ssvc-label">处置建议：{decision.label}</div>
              <div className="ssvc-text">{decision.text}</div>
              <div className="ssvc-factors">
                CISA SSVC 判定：{SSVC_TEXT[detail.ssvc.exploitation] ?? detail.ssvc.exploitation} ·{" "}
                {SSVC_TEXT[detail.ssvc.automatable] ?? detail.ssvc.automatable} ·{" "}
                {SSVC_TEXT[detail.ssvc.technicalImpact] ?? detail.ssvc.technicalImpact}
                <span className="muted">（简化决策，仅供参考）</span>
              </div>
            </div>
          )}

          <div className="kv">
            {(detail?.cvss || item.score) && (
              <div>
                <span>CVSS</span>
                <b>
                  {detail?.cvss?.score ?? item.score?.toFixed(1)} {detail?.cvss?.severity ?? ""}
                </b>
              </div>
            )}
            {epss && (
              <div>
                <span>EPSS 被利用概率</span>
                <b>
                  {pct(epss.epss, 2)}（高于 {pct(epss.pct, 1)} 的 CVE）
                </b>
              </div>
            )}
            {(item.dueDate || detail?.kevDateAdded) && (
              <div>
                <span>CISA KEV</span>
                <b>
                  {detail?.kevDateAdded ? `${detail.kevDateAdded.slice(0, 10)} 收录` : "已收录"}
                  {item.dueDate ? ` · 修复截止 ${item.dueDate}` : ""}
                </b>
              </div>
            )}
            <div>
              <span>公开 PoC</span>
              <b>{poc && poc.count > 0 ? `${poc.count} 个仓库，最高 ${poc.stars}★` : cve ? "未收录" : "—"}</b>
            </div>
            {detail?.published && (
              <div>
                <span>发布时间</span>
                <b>{date(detail.published)}</b>
              </div>
            )}
          </div>

          {loading && <div className="muted">正在加载 CVE 详情…</div>}
          {error && <div className="muted">详情加载失败：{error}</div>}

          {(detail?.description || item.summary) && (
            <section className="d-sec">
              <h4>漏洞描述</h4>
              <p>{detail?.description ?? item.summary}</p>
            </section>
          )}

          {cnFix && (
            <section className="d-sec">
              <h4>修复建议（长亭漏洞库）</h4>
              <p className="pre">{cnFix}</p>
            </section>
          )}

          {detail?.cwes && detail.cwes.length > 0 && (
            <section className="d-sec">
              <h4>漏洞类型（CWE）</h4>
              <div className="badges">
                {detail.cwes.map((c) => (
                  <a
                    key={c.id}
                    className="badge"
                    href={`https://cwe.mitre.org/data/definitions/${c.id.replace("CWE-", "")}.html`}
                    target="_blank"
                    rel="noreferrer"
                    title={c.name}
                  >
                    {c.id}
                  </a>
                ))}
              </div>
            </section>
          )}

          {detail?.affected && detail.affected.length > 0 && (
            <section className="d-sec">
              <h4>受影响产品</h4>
              <ul className="d-list">
                {detail.affected.map((a, i) => (
                  <li key={i}>
                    <b>
                      {a.vendor && a.vendor !== "n/a" ? `${a.vendor} ` : ""}
                      {a.product}
                    </b>
                    {a.versions.filter(Boolean).length > 0 && <span className="muted"> · {a.versions.filter(Boolean).join("，")}</span>}
                  </li>
                ))}
              </ul>
            </section>
          )}

          {poc && poc.top.length > 0 && (
            <section className="d-sec">
              <h4>公开 PoC（仅限授权测试使用）</h4>
              <ul className="d-list">
                {poc.top.map((p) => (
                  <li key={p.url}>
                    <a href={p.url} target="_blank" rel="noreferrer">
                      {p.name}
                    </a>{" "}
                    <span className="muted">★ {p.stars}</span>
                  </li>
                ))}
              </ul>
            </section>
          )}

          {related.length > 0 && (
            <section className="d-sec">
              <h4>同一漏洞的其它情报</h4>
              <ul className="d-list">
                {related.map((r) => (
                  <li key={`${r.source}-${r.id}`}>
                    <span className={`src ${SRC_CLASS[r.source]}`}>{r.sourceName}</span>{" "}
                    <a href={r.url} target="_blank" rel="noreferrer">
                      {r.title}
                    </a>
                  </li>
                ))}
              </ul>
            </section>
          )}

          {detail?.references && detail.references.length > 0 && (
            <section className="d-sec">
              <h4>参考链接</h4>
              <ul className="d-list refs">
                {detail.references.map((r) => (
                  <li key={r.url}>
                    <a href={r.url} target="_blank" rel="noreferrer">
                      {r.url}
                    </a>
                    {r.tags.length > 0 && <span className="muted"> · {r.tags.slice(0, 2).join(", ")}</span>}
                  </li>
                ))}
              </ul>
            </section>
          )}

          <div className="d-links">
            <a href={item.url} target="_blank" rel="noreferrer">
              查看原始来源 ↗
            </a>
            {cve && (
              <a href={`https://nvd.nist.gov/vuln/detail/${cve}`} target="_blank" rel="noreferrer">
                NVD ↗
              </a>
            )}
          </div>
        </div>
      </aside>
    </div>
  );
}
