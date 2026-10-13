import type { RawItem, SourceResult } from "../types";
import { loadConfig } from "../config";

interface KevEntry {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  knownRansomwareCampaignUse?: string;
}

/** CISA KEV — 已知被在野利用的漏洞目录（威胁情报） */
export async function fetchKev(): Promise<SourceResult> {
  const cfg = loadConfig();
  try {
    const res = await fetch(
      "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
      { headers: { "User-Agent": "security-radar/1.0" }, signal: AbortSignal.timeout(30000) },
    );
    if (!res.ok) throw new Error(`CISA KEV HTTP ${res.status}`);
    const data = (await res.json()) as { vulnerabilities?: KevEntry[] };

    const entries = (data.vulnerabilities ?? [])
      .slice()
      .sort((a, b) => b.dateAdded.localeCompare(a.dateAdded));

    const items: RawItem[] = entries.slice(0, cfg.limits.kev_max).map((e) => ({
      source: "kev" as const,
      sourceName: "CISA KEV",
      id: e.cveID,
      title: `${e.cveID} — ${e.vulnerabilityName}`,
      url: `https://nvd.nist.gov/vuln/detail/${e.cveID}`,
      summary: `${e.vendorProject} ${e.product}: ${e.shortDescription}`.slice(0, 500),
      severity: e.knownRansomwareCampaignUse === "Known" ? "勒索软件在野利用" : "在野利用",
      publishedAt: e.dateAdded,
      tags: [e.vendorProject.toLowerCase()],
      cve: e.cveID,
    }));

    return { source: "kev", ok: true, items, total: entries.length };
  } catch (error) {
    return { source: "kev", ok: false, items: [], error: String(error) };
  }
}
