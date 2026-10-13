import type { BriefingPoint, IntelSnapshot, RawItem, ScoredItem, SourceKind } from "./types";
import { unstable_cache } from "next/cache";
import { collectAll } from "./sources";

const CVE_RE = /CVE-\d{4}-\d{4,7}/gi;
const DAY = 24 * 3600 * 1000;

const SOURCE_LABEL: Record<SourceKind, string> = {
  cve: "NVD",
  ghsa: "GHSA",
  kev: "CISA KEV",
  news: "资讯",
};

/** 从条目中提取全部 CVE 编号（结构化字段 + 标题/摘要正文） */
function cvesOf(it: RawItem): string[] {
  const set = new Set<string>();
  if (it.cve) set.add(it.cve.toUpperCase());
  for (const m of `${it.title} ${it.summary ?? ""}`.matchAll(CVE_RE)) set.add(m[0].toUpperCase());
  return [...set];
}

function ageDays(iso?: string): number {
  if (!iso) return Infinity;
  const t = Date.parse(iso);
  return Number.isNaN(t) ? Infinity : (Date.now() - t) / DAY;
}

/**
 * 规则引擎：替代 LLM 摘要的可解释打分。
 * 在野利用 > 勒索关联 > CVSS 分值 > 多源印证 > 关注厂商命中 > 新鲜度。
 */
function score(it: RawItem, seenIn: SourceKind[]): { priority: number; reasons: string[] } {
  let p = 0;
  const reasons: string[] = [];
  if (it.source === "kev") {
    p += 70;
    reasons.push("在野利用");
    if (it.severity?.includes("勒索")) {
      p += 15;
      reasons.push("勒索软件关联");
    }
  }
  if (typeof it.score === "number" && it.score > 0) {
    p += it.score * 6;
    if (it.score >= 9) reasons.push(`CVSS ${it.score.toFixed(1)}`);
  } else if (it.severity === "CRITICAL") {
    p += 54;
    reasons.push("Critical");
  } else if (it.severity === "HIGH") {
    p += 42;
  }
  const others = seenIn.filter((s) => s !== it.source);
  if (others.length) {
    p += 12 * others.length;
    reasons.push(`多源印证（${others.map((s) => SOURCE_LABEL[s]).join("/")}）`);
  }
  if (it.tags?.length && it.source !== "kev") {
    p += 8;
    reasons.push(`关注厂商：${it.tags.slice(0, 2).join("、")}`);
  }
  const age = ageDays(it.publishedAt);
  if (age < 2) p += 10;
  else if (age < 7) p += 5;
  if (it.source === "news") p = Math.min(p, 30) + (others.length ? 20 : 0);
  return { priority: Math.round(p), reasons };
}

function buildBriefing(items: ScoredItem[], totals: Partial<Record<SourceKind, number>>): BriefingPoint[] {
  const out: BriefingPoint[] = [];
  const kev = items.filter((i) => i.source === "kev");
  const kevWeek = kev.filter((i) => ageDays(i.publishedAt) <= 7);
  const kevRansom = kev.filter((i) => i.severity?.includes("勒索"));
  if (kevWeek.length) {
    out.push({
      level: "critical",
      text: `CISA KEV 近 7 天新增 ${kevWeek.length} 个在野利用漏洞${
        kevRansom.length ? `，其中 ${kevRansom.length} 个与勒索软件活动相关` : ""
      }：${kevWeek
        .slice(0, 3)
        .map((i) => i.id)
        .join("、")}${kevWeek.length > 3 ? " 等" : ""}，应优先排查补丁。`,
    });
  } else if (kev.length) {
    out.push({ level: "high", text: `CISA KEV 最近一次更新收录 ${kev[0].id}（${kev[0].publishedAt}）。` });
  }

  const cves = items.filter((i) => i.source === "cve");
  const crit = cves.filter((i) => (i.score ?? 0) >= 9);
  if (cves.length) {
    const top = [...cves].sort((a, b) => (b.score ?? 0) - (a.score ?? 0))[0];
    out.push({
      level: crit.length ? "critical" : "high",
      text: `NVD 近 36 小时共有 ${totals.cve ?? cves.length} 条 CVE 更新，筛出 CVSS ≥ 7 的高危 ${cves.length} 条（≥ 9 的严重 ${crit.length} 条）；最高分 ${top.id}（${top.score?.toFixed(1)}）。`,
    });
  }

  const vendorHits = new Map<string, number>();
  for (const i of items) if (i.source !== "news") for (const t of i.tags ?? []) vendorHits.set(t, (vendorHits.get(t) ?? 0) + 1);
  const vendors = [...vendorHits.entries()].sort((a, b) => b[1] - a[1]).slice(0, 4);
  if (vendors.length) {
    out.push({
      level: "info",
      text: `涉及最多的厂商/组件：${vendors.map(([k, n]) => `${k}（${n}）`).join("、")}。`,
    });
  }

  const multi = items.filter((i) => i.source !== "news" && i.seenIn.length > 1);
  const multiIds = [...new Set(multi.map((i) => i.cve ?? i.id))];
  if (multiIds.length) {
    out.push({
      level: "high",
      text: `${multiIds.length} 个漏洞被多个情报源同时报道（${multiIds.slice(0, 3).join("、")}${multiIds.length > 3 ? " 等" : ""}），可信度与关注度更高。`,
    });
  }

  const ghsaCrit = items.filter((i) => i.source === "ghsa" && i.severity === "CRITICAL");
  if (ghsaCrit.length) {
    out.push({
      level: "high",
      text: `GitHub Advisory 新增 ${ghsaCrit.length} 条 Critical 级开源组件漏洞，最新：${ghsaCrit[0].title.slice(0, 80)}。`,
    });
  }

  const news = items.filter((i) => i.source === "news");
  if (news.length) {
    out.push({ level: "info", text: `安全资讯头条：${news[0].title}（${news[0].sourceName}）。` });
  }
  return out;
}

async function buildIntel(): Promise<IntelSnapshot> {
  const results = await collectAll();

  // CVE → 出现过的来源，用于跨源关联
  const index = new Map<string, Set<SourceKind>>();
  const all = results.flatMap((r) => r.items);
  for (const it of all) for (const c of cvesOf(it)) {
    if (!index.has(c)) index.set(c, new Set());
    index.get(c)!.add(it.source);
  }

  const items: ScoredItem[] = all.map((it) => {
    const ids = cvesOf(it);
    const seen = new Set<SourceKind>([it.source]);
    for (const c of ids) for (const s of index.get(c) ?? []) seen.add(s);
    const seenIn = [...seen];
    return { ...it, cve: it.cve ?? ids[0], seenIn, ...score(it, seenIn) };
  });

  const totals: Partial<Record<SourceKind, number>> = {};
  for (const r of results) totals[r.source] = r.total;

  // 去重后的优先处置清单：同一 CVE 只保留分最高的一条，每个来源最多 3 条以保证覆盖面
  const seenCve = new Set<string>();
  const perSource = new Map<SourceKind, number>();
  const top = [...items]
    .filter((i) => i.source !== "news")
    .sort((a, b) => b.priority - a.priority)
    .filter((i) => {
      const key = i.cve ?? i.id;
      if (seenCve.has(key) || (perSource.get(i.source) ?? 0) >= 3) return false;
      seenCve.add(key);
      perSource.set(i.source, (perSource.get(i.source) ?? 0) + 1);
      return true;
    })
    .slice(0, 6);

  return {
    fetchedAt: new Date().toISOString(),
    sources: results.map((r) => ({
      source: r.source,
      ok: r.ok,
      count: r.items.length,
      total: r.total,
      error: r.error ? r.error.slice(0, 160) : undefined,
    })),
    items,
    top,
    briefing: buildBriefing(items, totals),
  };
}

/**
 * 首页、JSON API、RSS 共用同一份快照（Vercel Data Cache，30 分钟），
 * 避免无 API Key 时对 NVD 的重复请求触发限流。
 */
export const getIntel = unstable_cache(buildIntel, ["intel-snapshot-v4"], { revalidate: 1800 });
