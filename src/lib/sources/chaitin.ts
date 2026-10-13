import type { RawItem, SourceResult } from "../types";
import { loadConfig } from "../config";

interface ChaitinVuln {
  id: string;
  ct_id?: string;
  title: string;
  summary?: string | null;
  severity?: string | null;
  cve_id?: string | null;
  fix_steps?: string | null;
  weakness?: string | null;
  disclosure_date?: string | null;
  created_at?: string | null;
}

/** 长亭漏洞库 — 中文高危漏洞（含修复建议），国内可直接访问 */
export async function fetchChaitin(): Promise<SourceResult> {
  const cfg = loadConfig();
  try {
    const res = await fetch(
      `https://stack.chaitin.com/api/v2/vuln/list/?limit=${cfg.limits.cn_max}&offset=0`,
      {
        headers: { "User-Agent": "Mozilla/5.0 security-radar/1.0", Accept: "application/json" },
        signal: AbortSignal.timeout(15000),
      },
    );
    if (!res.ok) throw new Error(`长亭漏洞库 HTTP ${res.status}`);
    const data = (await res.json()) as { data?: { list?: ChaitinVuln[]; count?: number } };
    const list = data.data?.list ?? [];

    const keywords = cfg.focus_keywords.map((k) => k.toLowerCase());
    const items: RawItem[] = list.slice(0, cfg.limits.cn_max).map((v) => {
      const hay = `${v.title} ${v.summary ?? ""}`.toLowerCase();
      return {
        source: "cn" as const,
        sourceName: "长亭漏洞库",
        id: v.ct_id || v.id,
        title: v.title,
        url: `https://stack.chaitin.com/vuldb/detail/${v.id}`,
        summary: (v.summary ?? "").slice(0, 400),
        severity: (v.severity ?? "").toUpperCase() || undefined,
        publishedAt: v.disclosure_date || v.created_at || undefined,
        cve: v.cve_id || undefined,
        fixSteps: (v.fix_steps ?? "").slice(0, 800) || undefined,
        tags: keywords.filter((k) => hay.includes(k)),
        lang: "zh" as const,
      };
    });

    return { source: "cn", ok: true, items, total: data.data?.count };
  } catch (error) {
    return { source: "cn", ok: false, items: [], error: String(error) };
  }
}
