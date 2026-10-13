import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "网络安全雷达 · Security Radar",
  description:
    "实时网络安全情报看板 — 聚合 NVD 高危 CVE、GitHub Advisory、CISA KEV 在野利用与安全资讯，规则引擎打分给出优先处置清单。",
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
                  <a href="/" style={{ color: "var(--text)" }}>
                    网络安全雷达
                  </a>
                </h1>
                <div className="sub">Security Radar · 实时威胁情报看板</div>
              </div>
            </div>
            <nav className="header-links">
              <a href="/api/intel">JSON API</a>
              <a href="/feed.xml">RSS</a>
              <a href="https://github.com/lzwhehe/security-radar" target="_blank" rel="noreferrer">
                GitHub
              </a>
            </nav>
          </header>
          {children}
          <footer className="footer">
            数据来自 NVD · GitHub Advisory · CISA KEV · The Hacker News / BleepingComputer / Krebs /
            Schneier，均为公开源；Next.js ISR 每 30 分钟服务端重新采集，无需任何密钥或数据库。
            <br />
            作者 刘卓文 ·{" "}
            <a href="https://github.com/lzwhehe/security-radar" target="_blank" rel="noreferrer">
              源码
            </a>{" "}
            · <a href="/feed.xml">订阅 RSS</a>
          </footer>
        </div>
      </body>
    </html>
  );
}
