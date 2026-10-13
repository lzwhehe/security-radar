import type { RawItem, SourceResult } from "../types";
import { loadConfig } from "../config";

interface NvdCve {
  cve: {
    id: string;
    descriptions: { lang: string; value: string }[];
    metrics?: {
      cvssMetricV31?: { cvssData: { baseScore: number; baseSeverity: string } }[];
      cvssMetricV30?: { cvssData: { baseScore: number; baseSeverity: string } }[];
      cvssMetricV2?: { cvssData: { baseScore: number }; baseSeverity?: string }[];
    };
    published: string;
    lastModified: string;
  };
}

function cvssOf(c: NvdCve["cve"]): { score: number; severity: string } {
  const m = c.metrics;
  const v31 = m?.cvssMetricV31?.[0]?.cvssData;
  if (v31) return { score: v31.baseScore, severity: v31.baseSeverity };
  const v30 = m?.cvssMetricV30?.[0]?.cvssData;
  if (v30) return { score: v30.baseScore, severity: v30.baseSeverity };
  const v2 = m?.cvssMetricV2?.[0];
  if (v2) return { score: v2.cvssData.baseScore, severity: v2.baseSeverity ?? "UNKNOWN" };
  return { score: 0, severity: "UNKNOWN" };
}

async function fetchWithRetry(
  url: string,
  headers: Record<string, string>,
  attempts: number,
): Promise<Response> {
  let lastErr: unknown;
  for (let i = 0; i < attempts; i++) {
    try {
      return await fetch(url, { headers, signal: AbortSignal.timeout(25000) });
    } catch (err) {
      lastErr = err;
      if (i < attempts - 1) await new Promise((r) => setTimeout(r, 3000));
    }
  }
  throw lastErr;
}

export async function fetchNvd(): Promise<SourceResult> {
  const cfg = loadConfig();
  try {
    const end = new Date();
    const start = new Date(end.getTime() - cfg.cve.lookback_hours * 3600 * 1000);
    const params = new URLSearchParams({
      lastModStartDate: start.toISOString(),
      lastModEndDate: end.toISOString(),
      resultsPerPage: "200",
    });
    const headers: Record<string, string> = { "User-Agent": "security-radar/1.0" };
    if (process.env.NVD_API_KEY) headers.apiKey = process.env.NVD_API_KEY;

    // NVD 不带 API Key 时较慢且限流：25s 超时、失败重试一次（需小于页面生成超时）
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?${params}`;
    const res = await fetchWithRetry(url, headers, 2);
    if (!res.ok) throw new Error(`NVD HTTP ${res.status}`);
    const data = (await res.json()) as { vulnerabilities?: NvdCve[]; totalResults?: number };

    const keywords = cfg.focus_keywords.map((k) => k.toLowerCase());
    const items: RawItem[] = [];
    for (const v of data.vulnerabilities ?? []) {
      const c = v.cve;
      const { score, severity } = cvssOf(c);
      if (score < cfg.cve.min_cvss) continue;
      const desc = c.descriptions.find((d) => d.lang === "en")?.value ?? "";
      const hay = `${c.id} ${desc}`.toLowerCase();
      const tags = keywords.filter((k) => hay.includes(k));
      items.push({
        source: "cve",
        sourceName: "NVD",
        id: c.id,
        title: c.id,
        url: `https://nvd.nist.gov/vuln/detail/${c.id}`,
        summary: desc.slice(0, 600),
        severity,
        score,
        publishedAt: c.published,
        tags,
        cve: c.id,
      });
    }

    items.sort((a, b) => {
      // 命中关注关键词的优先，其次按分数
      const ka = (a.tags?.length ? 1 : 0) - (b.tags?.length ? 1 : 0);
      if (ka !== 0) return -ka;
      return (b.score ?? 0) - (a.score ?? 0);
    });

    return {
      source: "cve",
      ok: true,
      items: items.slice(0, cfg.cve.max_items),
      total: data.totalResults ?? data.vulnerabilities?.length ?? 0,
    };
  } catch (error) {
    return { source: "cve", ok: false, items: [], error: String(error) };
  }
}
