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
  cn: { label: "中文漏洞库", desc: "长亭漏洞库" },
  news: { label: "安全资讯", desc: "中英文 RSS" },
};

function fmt(iso: string) {
  return new Date(iso).toLocaleString("zh-CN", { timeZone: "Asia/Shanghai", hour12: false });
}

function ms(v?: number) {
  if (v === undefined) return "";
  return v >= 1000 ? `${(v / 1000).toFixed(1)}s` : `${v}ms`;
}

export default async function Home() {
  const intel = await getIntel();
  const { enrich } = intel;

  return (
    <div>
      <section className="hero">
        <div className="live">
          <span className="dot" /> 实时采集 · 更新于 {fmt(intel.fetchedAt)}（北京时间）
        </div>
        <p className="hero-sub">
          聚合 NVD、GitHub Advisory、CISA KEV、长亭漏洞库与中英文安全媒体，结合 EPSS 被利用概率与公开 PoC，按「在野利用 →
          严重度 → 被利用概率 → 公开 PoC → 多源印证 → 关注厂商」规则打分，给出当日需要优先处置的漏洞。点击任一条目查看详情。
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

        <section className="panel">
          <h2 className="panel-title">🩺 数据源健康</h2>
          <table className="health">
            <tbody>
              {intel.sources.map((s) => (
                <tr key={s.source}>
                  <td>
                    <span className={`hdot ${s.ok ? "ok" : "bad"}`} />
                    {SOURCE_META[s.source].desc}
                  </td>
                  <td className="num">{s.ok ? `${s.count} 条` : "失败"}</td>
                  <td className="num">{ms(s.ms)}</td>
                </tr>
              ))}
              {intel.sources
                .flatMap((s) => s.feeds ?? [])
                .map((f) => (
                  <tr key={f.name} className="sub">
                    <td title={f.error}>
                      <span className={`hdot ${f.ok ? "ok" : "bad"}`} />
                      RSS · {f.name}
                    </td>
                    <td className="num">{f.ok ? `${f.count} 条` : "不可达"}</td>
                    <td className="num">{ms(f.ms)}</td>
                  </tr>
                ))}
              <tr>
                <td title={enrich.epss.error}>
                  <span className={`hdot ${enrich.epss.ok ? "ok" : "bad"}`} />
                  增强 · FIRST EPSS
                </td>
                <td className="num">{enrich.epss.ok ? `${enrich.epss.count} 个 CVE` : "失败"}</td>
                <td className="num">{ms(enrich.epss.ms)}</td>
              </tr>
              <tr>
                <td title={enrich.poc.error}>
                  <span className={`hdot ${enrich.poc.ok ? "ok" : "bad"}`} />
                  增强 · 公开 PoC
                </td>
                <td className="num">
                  {enrich.poc.ok ? `${enrich.poc.found}/${enrich.poc.checked} 有 PoC` : "失败"}
                </td>
                <td className="num">{ms(enrich.poc.ms)}</td>
              </tr>
            </tbody>
          </table>
          <div className="panel-note">单个源失败不影响整体，页面会自动降级；鼠标悬停可看错误原因</div>
        </section>
      </div>

      <IntelBoard items={intel.items} top={intel.top} />
    </div>
  );
}
