import { getIntel } from "@/lib/intel";

export const dynamic = "force-dynamic"; // 每次请求读共享缓存（unstable_cache）+ CDN s-maxage
export const maxDuration = 60;

function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

export async function GET() {
  const site = (process.env.SITE_URL || "https://agentradar-eight.vercel.app").replace(/\/$/, "");
  const intel = await getIntel();
  const items = intel.items
    .filter((i) => i.source !== "news")
    .sort((a, b) => b.priority - a.priority)
    .slice(0, 50)
    .map((i) => {
      const t = i.publishedAt ? Date.parse(i.publishedAt) : NaN;
      const pub = Number.isNaN(t) ? new Date(intel.fetchedAt) : new Date(t);
      const desc = `${i.reasons.join(" · ")}${i.reasons.length ? " — " : ""}${i.summary ?? ""}`;
      return `    <item>
      <title>${esc(`[${i.sourceName}] ${i.title}`)}</title>
      <link>${esc(i.url)}</link>
      <guid isPermaLink="false">${esc(`${i.source}:${i.id}`)}</guid>
      <pubDate>${pub.toUTCString()}</pubDate>
      <description>${esc(desc)}</description>
    </item>`;
    })
    .join("\n");

  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>网络安全雷达 Security Radar</title>
    <link>${site}</link>
    <description>实时网络安全情报 — 高危 CVE / 开源漏洞 / 在野利用，按规则引擎优先级排序</description>
    <language>zh-cn</language>
    <lastBuildDate>${new Date(intel.fetchedAt).toUTCString()}</lastBuildDate>
${items}
  </channel>
</rss>`;

  return new Response(xml, {
    headers: {
      "Content-Type": "application/xml; charset=utf-8",
      "Cache-Control": "public, s-maxage=1800, stale-while-revalidate=3600",
    },
  });
}
