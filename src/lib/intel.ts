import type {
  BriefingPoint,
  EnrichStatus,
  IntelSnapshot,
  PocInfo,
  RawItem,
  ScoredItem,
  SourceKind,
} from "./types";
import { unstable_cache } from "next/cache";
import { collectAll } from "./sources";
import { fetchEpss, fetchPocMany, type EpssScore } from "./enrich";

const CVE_RE = /CVE-\d{4}-\d{4,7}/gi;
const DAY = 24 * 3600 * 1000;
/** 每轮只给优先级最高的这么多个 CVE 查 PoC，控制外部请求量 */
const POC_CHECK_LIMIT = 60;

const SOURCE_LABEL: Record<SourceKind, string> = {
  cve: "NVD",
  ghsa: "GHSA",
  kev: "CISA KEV",
  cn: "长亭",
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

function daysUntil(date?: string): number | undefined {
  if (!date) return undefined;
  const t = Date.parse(`${date}T23:59:59Z`);
  return Number.isNaN(t) ? undefined : Math.floor((t - Date.now()) / DAY);
}

interface Signals {
  epss?: EpssScore;
  poc?: PocInfo;
}

/**
 * 规则引擎：可解释打分，每一分都写进 reasons。
 * 在野利用 > 勒索关联 > 严重度 > 被利用概率(EPSS) > 公开 PoC > 多源印证 > 关注厂商 > 新鲜度。
 */
function score(it: RawItem, seenIn: SourceKind[], sig: Signals): { priority: number; reasons: string[] } {
  let p = 0;
  const reasons: string[] = [];
  if (it.source === "kev") {
    p += 70;
    reasons.push("在野利用");
    if (it.ransomware) {
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
  if (sig.epss && it.source !== "news") {
    p += sig.epss.pct * 25;
    if (sig.epss.epss >= 0.1) reasons.push(`EPSS ${(sig.epss.epss * 100).toFixed(0)}%`);
    else if (sig.epss.pct >= 0.95) reasons.push(`EPSS 前 ${((1 - sig.epss.pct) * 100).toFixed(1)}%`);
  }
  if (sig.poc && sig.poc.count > 0 && it.source !== "news") {
    p += 12;
    reasons.push(`公开 PoC ×${sig.poc.count}`);
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
  const kevRansom = kev.filter((i) => i.ransomware);
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

  // CISA KEV 修复截止：分开统计已逾期和 7 天内到期，并给出近期 CISA 给的修复期长度
  const overdue = kev.filter((i) => i.kevDueDays !== undefined && i.kevDueDays < 0);
  const dueSoon = kev.filter((i) => i.kevDueDays !== undefined && i.kevDueDays >= 0 && i.kevDueDays <= 7);
  if (overdue.length || dueSoon.length) {
    const windows = kev
      .map((i) => (i.dueDate && i.publishedAt ? (Date.parse(i.dueDate) - Date.parse(i.publishedAt)) / DAY : NaN))
      .filter((d) => !Number.isNaN(d))
      .sort((a, b) => a - b);
    const median = windows.length ? windows[Math.floor(windows.length / 2)] : undefined;
    const parts: string[] = [];
    if (dueSoon.length) parts.push(`${dueSoon.length} 个将在 7 天内到期（${dueSoon.slice(0, 3).map((i) => i.id).join("、")}）`);
    if (overdue.length) parts.push(`${overdue.length} 个已过截止日`);
    out.push({
      level: "critical",
      text: `KEV 修复截止：${parts.join("，")}${
        median !== undefined ? `；CISA 近期给新收录漏洞的修复期中位数仅 ${Math.round(median)} 天，需要更快的补丁节奏` : ""
      }。`,
    });
  }

  const withPoc = dedupeByCve(items.filter((i) => i.source !== "news" && (i.poc?.count ?? 0) > 0)).sort(
    (a, b) => (b.poc?.stars ?? 0) - (a.poc?.stars ?? 0),
  );
  if (withPoc.length) {
    const t = withPoc[0];
    out.push({
      level: "high",
      text: `${withPoc.length} 个漏洞已有公开 PoC，武器化风险高；关注度最高的是 ${t.cve}（${t.poc!.count} 个 PoC 仓库，最高 ${t.poc!.stars}★）。`,
    });
  }

  const hotEpss = dedupeByCve(items.filter((i) => i.source !== "news" && (i.epssPct ?? 0) >= 0.99)).sort(
    (a, b) => (b.epss ?? 0) - (a.epss ?? 0),
  );
  if (hotEpss.length) {
    out.push({
      level: "high",
      text: `${hotEpss.length} 个漏洞的 EPSS 位于全部 CVE 的前 1%（未来 30 天被利用概率最高）：${hotEpss
        .slice(0, 3)
        .map((i) => `${i.cve}（${((i.epss ?? 0) * 100).toFixed(0)}%）`)
        .join("、")}。`,
    });
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

  const cn = items.filter((i) => i.source === "cn");
  if (cn.length) {
    out.push({
      level: "info",
      text: `长亭漏洞库最新收录：${cn[0].title}${cn[0].fixSteps ? "（已附中文修复建议）" : ""}。`,
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

  const multiIds = [...new Set(items.filter((i) => i.source !== "news" && i.seenIn.length > 1).map((i) => i.cve ?? i.id))];
  if (multiIds.length) {
    out.push({
      level: "high",
      text: `${multiIds.length} 个漏洞被多个情报源同时报道（${multiIds.slice(0, 3).join("、")}${multiIds.length > 3 ? " 等" : ""}），可信度与关注度更高。`,
    });
  }

  const news = items.filter((i) => i.source === "news");
  if (news.length) {
    out.push({ level: "info", text: `安全资讯头条：${news[0].title}（${news[0].sourceName}）。` });
  }
  return out;
}

function dedupeByCve(items: ScoredItem[]): ScoredItem[] {
  const seen = new Set<string>();
  return items.filter((i) => {
    if (!i.cve || seen.has(i.cve)) return false;
    seen.add(i.cve);
    return true;
  });
}

async function buildIntel(): Promise<IntelSnapshot> {
  const results = await collectAll();

  // CVE → 出现过的来源，用于跨源关联
  const index = new Map<string, Set<SourceKind>>();
  const all = results.flatMap((r) => r.items);
  for (const it of all)
    for (const c of cvesOf(it)) {
      if (!index.has(c)) index.set(c, new Set());
      index.get(c)!.add(it.source);
    }

  const base = all.map((it) => {
    const ids = cvesOf(it);
    const seen = new Set<SourceKind>([it.source]);
    for (const c of ids) for (const s of index.get(c) ?? []) seen.add(s);
    return { it, cve: it.cve?.toUpperCase() ?? ids[0], seenIn: [...seen] };
  });

  // 增强信号：EPSS（全部漏洞类 CVE）+ 公开 PoC（初步打分最高的若干个）
  const vulnCves = [...new Set(base.filter((b) => b.it.source !== "news" && b.cve).map((b) => b.cve!))];
  const enrich: EnrichStatus = {
    epss: { ok: false, count: 0, ms: 0 },
    poc: { ok: false, checked: 0, found: 0, ms: 0 },
  };

  let epssMap = new Map<string, EpssScore>();
  let started = Date.now();
  try {
    epssMap = await fetchEpss(vulnCves);
    enrich.epss = { ok: true, count: epssMap.size, ms: Date.now() - started };
  } catch (error) {
    enrich.epss = { ok: false, count: 0, ms: Date.now() - started, error: String(error).slice(0, 160) };
  }

  const prelim = base
    .filter((b) => b.it.source !== "news" && b.cve)
    .map((b) => ({ cve: b.cve!, p: score(b.it, b.seenIn, { epss: epssMap.get(b.cve!) }).priority }))
    .sort((a, b) => b.p - a.p);
  const pocTargets = [...new Set(prelim.map((x) => x.cve))].slice(0, POC_CHECK_LIMIT);

  let pocMap = new Map<string, PocInfo>();
  started = Date.now();
  try {
    const { map, failed } = await fetchPocMany(pocTargets);
    pocMap = map;
    const found = [...map.values()].filter((v) => v.count > 0).length;
    enrich.poc = {
      ok: failed < pocTargets.length || pocTargets.length === 0,
      checked: pocTargets.length,
      found,
      ms: Date.now() - started,
      error: failed ? `${failed} 个查询失败` : undefined,
    };
  } catch (error) {
    enrich.poc = { ok: false, checked: 0, found: 0, ms: Date.now() - started, error: String(error).slice(0, 160) };
  }

  const items: ScoredItem[] = base.map(({ it, cve, seenIn }) => {
    const sig: Signals = cve ? { epss: epssMap.get(cve), poc: pocMap.get(cve) } : {};
    return {
      ...it,
      cve,
      seenIn,
      epss: sig.epss?.epss,
      epssPct: sig.epss?.pct,
      poc: sig.poc && sig.poc.count > 0 ? sig.poc : undefined,
      kevDueDays: it.source === "kev" ? daysUntil(it.dueDate) : undefined,
      ...score(it, seenIn, sig),
    };
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
      ms: r.ms,
      feeds: r.feeds,
      error: r.error ? r.error.slice(0, 200) : undefined,
    })),
    enrich,
    items,
    top,
    briefing: buildBriefing(items, totals),
  };
}

/**
 * 首页、JSON API、RSS 共用同一份快照（Data Cache，30 分钟），
 * 避免无 API Key 时对 NVD / EPSS / PoC 镜像的重复请求。
 */
export const getIntel = unstable_cache(buildIntel, ["intel-snapshot-v5"], { revalidate: 1800 });
