import type { PocInfo } from "./types";

const CVE_ID = /^CVE-\d{4}-\d{4,7}$/;

/** PoC-in-GitHub 数据源；raw.githubusercontent.com 在国内被墙，默认走 jsDelivr 镜像 */
const POC_BASE = (process.env.POC_BASE || "https://fastly.jsdelivr.net/gh/nomi-sec/PoC-in-GitHub@master").replace(
  /\/$/,
  "",
);

export interface EpssScore {
  epss: number;
  pct: number;
}

/**
 * FIRST EPSS：未来 30 天被利用的概率与百分位。免 key；
 * 实测单次超过约 130 个 CVE 会静默返回空，所以按 100 个一批。EPSS 每天更新一次，缓存 6 小时。
 */
export async function fetchEpss(cves: string[]): Promise<Map<string, EpssScore>> {
  const ids = [...new Set(cves.map((c) => c.toUpperCase()).filter((c) => CVE_ID.test(c)))];
  const out = new Map<string, EpssScore>();
  for (let i = 0; i < ids.length; i += 100) {
    const batch = ids.slice(i, i + 100);
    const res = await fetch(`https://api.first.org/data/v1/epss?cve=${batch.join(",")}&limit=${batch.length}`, {
      headers: { "User-Agent": "security-radar/1.0" },
      signal: AbortSignal.timeout(15000),
      next: { revalidate: 21600 },
    });
    if (!res.ok) throw new Error(`EPSS HTTP ${res.status}`);
    const data = (await res.json()) as { data?: { cve: string; epss: string; percentile: string }[] };
    for (const d of data.data ?? []) {
      out.set(d.cve.toUpperCase(), { epss: Number(d.epss), pct: Number(d.percentile) });
    }
  }
  return out;
}

interface PocRepo {
  full_name: string;
  html_url: string;
  stargazers_count?: number;
}

/** 单个 CVE 的公开 PoC（GitHub 仓库）；404 表示没有收录 PoC */
export async function fetchPoc(cve: string, topN = 3): Promise<PocInfo | null> {
  const id = cve.toUpperCase();
  if (!CVE_ID.test(id)) return null;
  const year = id.split("-")[1];
  const res = await fetch(`${POC_BASE}/${year}/${id}.json`, {
    headers: { "User-Agent": "security-radar/1.0" },
    signal: AbortSignal.timeout(10000),
    next: { revalidate: 43200 },
  });
  if (res.status === 404) return { count: 0, stars: 0, top: [] };
  if (!res.ok) throw new Error(`PoC HTTP ${res.status}`);
  const repos = (await res.json()) as PocRepo[];
  const sorted = [...repos].sort((a, b) => (b.stargazers_count ?? 0) - (a.stargazers_count ?? 0));
  return {
    count: repos.length,
    stars: sorted[0]?.stargazers_count ?? 0,
    top: sorted.slice(0, topN).map((r) => ({ name: r.full_name, url: r.html_url, stars: r.stargazers_count ?? 0 })),
  };
}

/** 并发受限地批量查询 PoC；单个失败不影响其它，返回失败数用于健康面板 */
export async function fetchPocMany(
  cves: string[],
  concurrency = 6,
): Promise<{ map: Map<string, PocInfo>; failed: number }> {
  const queue = [...new Set(cves.map((c) => c.toUpperCase()))];
  const map = new Map<string, PocInfo>();
  let failed = 0;
  async function worker() {
    for (let id = queue.shift(); id; id = queue.shift()) {
      try {
        const info = await fetchPoc(id);
        if (info) map.set(id, info);
      } catch {
        failed++;
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, queue.length) }, worker));
  return { map, failed };
}
