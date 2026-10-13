import type { Metadata } from "next";
import "./globals.css";

const BASE = process.env.NEXT_PUBLIC_BASE_PATH || "";

export const metadata: Metadata = {
  title: "网络安全雷达 · Security Radar",
  description:
    "实时网络安全情报看板 — 聚合 NVD 高危 CVE、GitHub Advisory、CISA KEV 在野利用、长亭漏洞库与中英文安全资讯，结合 EPSS 与公开 PoC 打分，给出优先处置清单。",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="zh-CN">
      <body>
        <div className="container">
          <header className="site-header">
            <div className="brand">
              <span className="logo">🛡️</span>
              <div>
                <h1>
                  <a href={`${BASE}/`} style={{ color: "var(--text)" }}>
                    网络安全雷达
                  </a>
                </h1>
                <div className="sub">Security Radar · 实时威胁情报看板</div>
              </div>
            </div>
            <nav className="header-links">
              <a href={`${BASE}/api/intel`}>JSON API</a>
              <a href={`${BASE}/feed.xml`}>RSS</a>
              <a href="https://github.com/lzwhehe/security-radar" target="_blank" rel="noreferrer">
                GitHub
              </a>
            </nav>
          </header>
          {children}
          <footer className="footer">
            漏洞数据：NVD · GitHub Advisory · CISA KEV · 长亭漏洞库；增强信号：FIRST EPSS · PoC-in-GitHub · MITRE CVE（含
            CISA SSVC）；资讯：安全客 · 先知社区 · Seebug Paper · Krebs · Schneier 等。全部为公开源，服务端每 30
            分钟重新采集，无需任何密钥或数据库。
            <br />
            作者 刘卓文 ·{" "}
            <a href="https://github.com/lzwhehe/security-radar" target="_blank" rel="noreferrer">
              源码
            </a>{" "}
            · <a href={`${BASE}/feed.xml`}>订阅 RSS</a>
          </footer>
        </div>
      </body>
    </html>
  );
}
