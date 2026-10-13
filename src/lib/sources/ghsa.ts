import type { RawItem, SourceResult } from "../types";
import { loadConfig } from "../config";

interface Advisory {
  ghsa_id: string;
  summary: string;
  description: string;
  severity: string;
  html_url: string;
  published_at: string;
  cve_id?: string | null;
  vulnerabilities?: { package?: { ecosystem?: string; name?: string } }[];
}

/** GitHub 安全公告（GHSA）— 包含 reviewed 的供应链/开源漏洞，多数含 PoC/补丁信息 */
export async function fetchGhsa(): Promise<SourceResult> {
  const cfg = loadConfig();
  try {
    const headers: Record<string, string> = {
      Accept: "application/vnd.github+json",
      "User-Agent": "security-radar/1.0",
      "X-GitHub-Api-Version": "2022-11-28",
    };
    if (process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;

    const params = new URLSearchParams({
      sort: "published",
      direction: "desc",
      per_page: "60",
      type: "reviewed",
    });
    const res = await fetch(`https://api.github.com/advisories?${params}`, {
      headers,
      signal: AbortSignal.timeout(30000),
    });
    if (!res.ok) throw new Error(`GitHub Advisories HTTP ${res.status}`);
    const data = (await res.json()) as Advisory[];

    const keywords = cfg.focus_keywords.map((k) => k.toLowerCase());
    const items: RawItem[] = data
      .filter((a) => ["critical", "high"].includes((a.severity || "").toLowerCase()))
      .map((a) => {
        const hay = `${a.summary} ${a.description}`.toLowerCase();
        const pkg = a.vulnerabilities?.[0]?.package;
        return {
          source: "ghsa" as const,
          sourceName: "GitHub Advisory",
          id: a.ghsa_id,
          title: a.cve_id ? `${a.cve_id} — ${a.summary}` : a.summary,
          url: a.html_url,
          summary: (a.description || a.summary || "").slice(0, 500),
          severity: a.severity?.toUpperCase(),
          publishedAt: a.published_at,
          tags: keywords.filter((k) => hay.includes(k)),
          cve: a.cve_id ?? undefined,
          ...(pkg?.ecosystem ? { sourceName: `GitHub Advisory · ${pkg.ecosystem}${pkg.name ? ` / ${pkg.name}` : ""}` } : {}),
        };
      });

    return { source: "ghsa", ok: true, items: items.slice(0, cfg.limits.ghsa_max), total: data.length };
  } catch (error) {
    return { source: "ghsa", ok: false, items: [], error: String(error) };
  }
}
