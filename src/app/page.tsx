import { getIntel } from "@/lib/intel";
import type { SourceKind } from "@/lib/types";
import IntelBoard from "./IntelBoard";

// ISR：每 30 分钟在服务端重新采集一次公开数据源，无需任何密钥与数据库
export const revalidate = 1800;
export const maxDuration = 60;

const SOURCE_META: Record<SourceKind, { label: string; desc: string }> = {
  cve: { label: "高危 CVE", desc: "NVD · CVSS ≥ 7" },
  ghsa: { label: "开源组件漏洞", desc: "GitHub Advisory" },
  kev: { label: "在野利用", desc: "CISA KEV" },
  news: { label: "安全资讯", desc: "RSS × 4" },
};

function fmt(iso: string) {
  return new Date(iso).toLocaleString("zh-CN", { timeZone: "Asia/Shanghai", hour12: false });
}

export default async function Home() {
  const intel = await getIntel();

  return (
    <div>
      <section className="hero">
        <div className="live">
          <span className="dot" /> 实时采集 · 更新于 {fmt(intel.fetchedAt)}（北京时间）
        </div>
        <p className="hero-sub">
          聚合 NVD、GitHub Advisory、CISA KEV 与主流安全媒体，按「在野利用 → 严重度 → 多源印证 →
          关注厂商」规则打分排序，给出当日需要优先处置的漏洞。
        </p>
      </section>

      <section className="stats">
        {intel.sources.map((s) => (
          <div key={s.source} className={`stat stat-${s.source} ${s.ok ? "" : "stat-down"}`}>
            <div className="stat-num">{s.ok ? s.count : "—"}</div>
            <div className="stat-label">{SOURCE_META[s.source].label}</div>
            <div className="stat-desc">
              {SOURCE_META[s.source].desc}
              {s.ok && s.total !== undefined && s.source === "kev" ? ` · 目录共 ${s.total} 条` : ""}
              {s.ok && s.total !== undefined && s.source === "cve" ? ` · 36h 内更新 ${s.total} 条` : ""}
              {!s.ok ? " · 数据源暂不可用" : ""}
            </div>
          </div>
        ))}
      </section>

      <div className="grid2">
        {intel.briefing.length > 0 && (
          <section className="panel">
            <h2 className="panel-title">📋 今日要点</h2>
            <ul className="briefing">
              {intel.briefing.map((b, i) => (
                <li key={i} className={`bp bp-${b.level}`}>
                  {b.text}
                </li>
              ))}
            </ul>
            <div className="panel-note">由规则引擎根据实时数据自动生成</div>
          </section>
        )}

        {intel.top.length > 0 && (
          <section className="panel">
            <h2 className="panel-title">🚨 优先处置 Top {intel.top.length}</h2>
            <ol className="top-list">
              {intel.top.map((t) => (
                <li key={`${t.source}-${t.id}`}>
                  <div className="top-head">
                    <span className="prio" title="规则引擎优先级">
                      {t.priority}
                    </span>
                    <a href={t.url} target="_blank" rel="noreferrer" className="top-title">
                      {t.title === t.id && t.summary
                        ? `${t.id} — ${t.summary.slice(0, 90)}${t.summary.length > 90 ? "…" : ""}`
                        : t.title}
                    </a>
                  </div>
                  <div className="reasons">
                    {t.reasons.map((r) => (
                      <span key={r} className="reason">
                        {r}
                      </span>
                    ))}
                  </div>
                </li>
              ))}
            </ol>
          </section>
        )}
      </div>

      <IntelBoard items={intel.items} />
    </div>
  );
}
