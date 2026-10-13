"use client";

import { useMemo, useState } from "react";
import type { ScoredItem, SourceKind } from "@/lib/types";

const TABS: { key: "all" | SourceKind; label: string }[] = [
  { key: "all", label: "全部" },
  { key: "kev", label: "在野利用 KEV" },
  { key: "cve", label: "高危 CVE" },
  { key: "ghsa", label: "GitHub Advisory" },
  { key: "news", label: "安全资讯" },
];

const SRC_CLASS: Record<SourceKind, string> = { cve: "s-cve", ghsa: "s-ghsa", kev: "s-kev", news: "s-news" };

function sevClass(it: ScoredItem): string {
  if (it.source === "news") return "sev-info";
  if (it.source === "kev") return it.severity?.includes("勒索") ? "sev-crit" : "sev-high";
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

export default function IntelBoard({ items }: { items: ScoredItem[] }) {
  const [tab, setTab] = useState<"all" | SourceKind>("all");
  const [q, setQ] = useState("");
  const [sort, setSort] = useState<"priority" | "time">("priority");

  const counts = useMemo(() => {
    const c: Record<string, number> = { all: items.length };
    for (const i of items) c[i.source] = (c[i.source] ?? 0) + 1;
    return c;
  }, [items]);

  const shown = useMemo(() => {
    const kw = q.trim().toLowerCase();
    return items
      .filter((i) => tab === "all" || i.source === tab)
      .filter(
        (i) =>
          !kw ||
          `${i.id} ${i.title} ${i.summary ?? ""} ${i.sourceName} ${(i.tags ?? []).join(" ")}`
            .toLowerCase()
            .includes(kw),
      )
      .sort((a, b) =>
        sort === "priority"
          ? b.priority - a.priority
          : (Date.parse(b.publishedAt ?? "") || 0) - (Date.parse(a.publishedAt ?? "") || 0),
      );
  }, [items, tab, q, sort]);

  return (
    <section className="board">
      <div className="toolbar">
        <div className="tabs">
          {TABS.map((t) => (
            <button
              key={t.key}
              className={`tab ${tab === t.key ? "active" : ""}`}
              onClick={() => setTab(t.key)}
            >
              {t.label} <span className="tab-n">{counts[t.key] ?? 0}</span>
            </button>
          ))}
        </div>
        <div className="controls">
          <input
            className="search"
            placeholder="搜索 CVE 编号 / 厂商 / 关键词，如 fortinet"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
          <select
            className="sort"
            value={sort}
            onChange={(e) => setSort(e.target.value as "priority" | "time")}
          >
            <option value="priority">按优先级</option>
            <option value="time">按时间</option>
          </select>
        </div>
      </div>

      {shown.length === 0 ? (
        <div className="empty">没有匹配的情报</div>
      ) : (
        <div className="list">
          {shown.map((it) => (
            <article key={`${it.source}-${it.id}`} className={`item ${sevClass(it)}`}>
              <div className="item-head">
                <span className={`src ${SRC_CLASS[it.source]}`}>{it.sourceName}</span>
                {it.score ? <span className="score">CVSS {it.score.toFixed(1)}</span> : null}
                {it.severity && !it.score ? <span className="sev">{it.severity}</span> : null}
                <span className="when">{date(it.publishedAt)}</span>
                <span className="prio-sm" title="规则引擎优先级">
                  P{it.priority}
                </span>
              </div>
              <a className="item-title" href={it.url} target="_blank" rel="noreferrer">
                {it.title}
              </a>
              {it.summary ? <p className="item-sum">{it.summary}</p> : null}
              {(it.tags?.length || it.seenIn.length > 1) && (
                <div className="badges">
                  {it.seenIn.length > 1 && (
                    <span className="badge badge-multi">多源印证 ×{it.seenIn.length}</span>
                  )}
                  {(it.tags ?? []).map((t) => (
                    <span key={t} className="badge">
                      #{t}
                    </span>
                  ))}
                </div>
              )}
            </article>
          ))}
        </div>
      )}
    </section>
  );
}
