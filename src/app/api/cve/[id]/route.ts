import { fetchEpss, fetchPoc } from "@/lib/enrich";

// CVE 详情：MITRE CVE 记录（含 CISA ADP 的 SSVC 判定）+ EPSS + 公开 PoC，按需加载
export const dynamic = "force-dynamic";
export const maxDuration = 30;

const CVE_ID = /^CVE-\d{4}-\d{4,7}$/;

interface CveRecord {
  cveMetadata?: { datePublished?: string; dateUpdated?: string };
  containers?: {
    cna?: CveContainer & { descriptions?: { lang: string; value: string }[] };
    adp?: (CveContainer & { title?: string })[];
  };
}

interface CveContainer {
  problemTypes?: { descriptions?: { cweId?: string; description?: string }[] }[];
  affected?: {
    vendor?: string;
    product?: string;
    versions?: { version?: string; status?: string; lessThan?: string; lessThanOrEqual?: string }[];
  }[];
  references?: { url: string; name?: string; tags?: string[] }[];
  metrics?: Record<string, unknown>[];
}

interface CvssData {
  baseScore?: number;
  baseSeverity?: string;
  vectorString?: string;
}

function pickCvss(metrics: Record<string, unknown>[] = []): CvssData | undefined {
  for (const key of ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"]) {
    const m = metrics.find((x) => x[key]);
    if (m) return { ...(m[key] as CvssData), vectorString: (m[key] as CvssData).vectorString };
  }
  return undefined;
}

type AdpContainer = CveContainer & { title?: string };

function ssvcOf(adp: AdpContainer[]) {
  for (const a of adp) {
    for (const m of a.metrics ?? []) {
      const other = m.other as { type?: string; content?: { options?: Record<string, string>[] } } | undefined;
      if (other?.type !== "ssvc") continue;
      const opts = Object.assign({}, ...(other.content?.options ?? [])) as Record<string, string>;
      const exploitation = (opts.Exploitation ?? "").toLowerCase();
      const automatable = (opts.Automatable ?? "").toLowerCase();
      const impact = (opts["Technical Impact"] ?? "").toLowerCase();
      return { exploitation, automatable, technicalImpact: impact, decision: decide(exploitation, automatable, impact) };
    }
  }
  return undefined;
}

/** 参考 CISA SSVC 的简化决策：利用状态 × 是否可自动化 × 技术影响 */
function decide(exploitation: string, automatable: string, impact: string) {
  const auto = automatable === "yes";
  const total = impact === "total";
  if (exploitation === "active") return auto || total ? "Act" : "Attend";
  if (exploitation === "poc") return auto && total ? "Attend" : "Track*";
  return auto && total ? "Track*" : "Track";
}

function formatVersions(v: NonNullable<CveContainer["affected"]>[number]["versions"] = []): string[] {
  return v.slice(0, 6).map((x) => {
    if (x.lessThan) return `${x.version && x.version !== "0" ? `${x.version} ≤ ` : ""}< ${x.lessThan}`;
    if (x.lessThanOrEqual) return `${x.version && x.version !== "0" ? `${x.version} ≤ ` : ""}≤ ${x.lessThanOrEqual}`;
    return x.version ?? "";
  });
}

export async function GET(_request: Request, { params }: { params: { id: string } }) {
  const id = decodeURIComponent(params.id).toUpperCase();
  if (!CVE_ID.test(id)) return Response.json({ error: "无效的 CVE 编号" }, { status: 400 });

  const [record, epss, poc] = await Promise.allSettled([
    fetch(`https://cveawg.mitre.org/api/cve/${id}`, {
      headers: { "User-Agent": "security-radar/1.0" },
      signal: AbortSignal.timeout(15000),
      next: { revalidate: 86400 },
    }).then(async (r) => {
      if (r.status === 404) return null;
      if (!r.ok) throw new Error(`MITRE HTTP ${r.status}`);
      return (await r.json()) as CveRecord;
    }),
    fetchEpss([id]),
    fetchPoc(id, 5),
  ]);

  const rec = record.status === "fulfilled" ? record.value : null;
  const cna = rec?.containers?.cna;
  const adp = rec?.containers?.adp ?? [];
  const containers: CveContainer[] = [cna ?? {}, ...adp];

  const cwes = new Map<string, string>();
  for (const c of containers)
    for (const pt of c.problemTypes ?? [])
      for (const d of pt.descriptions ?? []) if (d.cweId) cwes.set(d.cweId, d.description ?? d.cweId);

  const cvss = pickCvss(cna?.metrics) ?? adp.map((a) => pickCvss(a.metrics)).find(Boolean);
  const kevAdp = adp
    .flatMap((a) => a.metrics ?? [])
    .map((m) => m.other as { type?: string; content?: { dateAdded?: string } } | undefined)
    .find((o) => o?.type === "kev");

  const body = {
    id,
    found: Boolean(rec),
    description: cna?.descriptions?.find((d) => d.lang?.startsWith("en"))?.value ?? cna?.descriptions?.[0]?.value,
    published: rec?.cveMetadata?.datePublished,
    updated: rec?.cveMetadata?.dateUpdated,
    cvss: cvss ? { score: cvss.baseScore, severity: cvss.baseSeverity, vector: cvss.vectorString } : undefined,
    cwes: [...cwes].map(([cweId, name]) => ({ id: cweId, name })),
    affected: (cna?.affected ?? []).slice(0, 8).map((a) => ({
      vendor: a.vendor,
      product: a.product,
      versions: formatVersions(a.versions),
    })),
    references: (cna?.references ?? []).slice(0, 12).map((r) => ({ url: r.url, tags: r.tags ?? [] })),
    ssvc: ssvcOf(adp),
    kevDateAdded: kevAdp?.content?.dateAdded,
    epss: epss.status === "fulfilled" ? epss.value.get(id) : undefined,
    poc: poc.status === "fulfilled" ? poc.value : undefined,
    errors: [record, epss, poc]
      .filter((r): r is PromiseRejectedResult => r.status === "rejected")
      .map((r) => String(r.reason).slice(0, 120)),
  };

  return Response.json(body, {
    headers: { "Cache-Control": "public, s-maxage=86400, stale-while-revalidate=172800" },
  });
}
