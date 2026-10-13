# 🛡️ 网络安全雷达 · Security Radar

**在线 Demo：<https://agentradar-eight.vercel.app>**（打开即看，无需登录）

实时网络安全情报看板：聚合 **NVD 高危 CVE、GitHub Advisory、CISA KEV（在野利用）与主流安全媒体 RSS**，
用可解释的规则引擎为每条情报打分，给出「今日要点」与「优先处置 Top N」，并提供 JSON API 与 RSS 订阅。

全部数据源都是公开免费接口，**部署不需要任何 API Key、数据库或付费服务**。

## 功能

| 功能 | 说明 |
| --- | --- |
| 多源采集 | NVD CVE API 2.0（近 36h 更新、CVSS ≥ 7）、GitHub Advisory（reviewed, Critical/High）、CISA KEV 目录、4 个安全媒体 RSS/Atom |
| 跨源关联 | 从结构化字段与正文中提取 CVE 编号，标出被多个情报源同时报道的漏洞（多源印证） |
| 规则引擎打分 | 在野利用 > 勒索软件关联 > CVSS / 严重度 > 多源印证 > 关注厂商命中 > 新鲜度，每条给出打分理由 |
| 今日要点 | 根据实时数据自动生成的情报摘要（KEV 新增、严重 CVE 数、高频厂商、多源印证、头条资讯） |
| 交互看板 | 按来源筛选、关键词 / CVE 编号搜索、按优先级或时间排序，移动端适配 |
| 开放接口 | `GET /api/intel` 返回完整 JSON 快照；`/feed.xml` 按优先级输出 RSS |

## 架构

```
            ┌── NVD CVE API ──┐
            ├── GitHub Advisory ┤
请求 ──► Next.js (Vercel) ──► unstable_cache (30 min) ──► collectAll() ─┤
            ├── CISA KEV JSON ─┤
            └── 安全媒体 RSS ───┘
                     │
                     ▼
         规则引擎：CVE 提取 → 跨源关联 → 打分 → 今日要点 / Top N
                     │
         ┌───────────┼─────────────┐
       首页 (ISR)   /api/intel     /feed.xml
```

- **Next.js 14 App Router + TypeScript**，首页使用 ISR（`revalidate = 1800`）每 30 分钟在服务端重新采集。
- 三个出口共用一份 `unstable_cache` 快照，避免在没有 NVD API Key 时重复请求触发限流。
- 单个数据源失败不影响整体：看板会标记该源「暂不可用」，其余照常展示。

| 文件 | 作用 |
| --- | --- |
| `src/lib/sources/*.ts` | 四类数据源采集器 |
| `src/lib/intel.ts` | 跨源关联、规则引擎打分、要点生成 |
| `src/app/page.tsx` / `IntelBoard.tsx` | 看板页面（服务端渲染 + 客户端筛选） |
| `src/app/api/intel/route.ts` | JSON API |
| `src/app/feed.xml/route.ts` | RSS |
| `config.yml` | CVSS 阈值、回溯时长、关注厂商、RSS 源、各源条数上限 |

## 本地运行

```bash
npm install
npm run dev     # http://localhost:3000
```

可选环境变量（不填也能运行）：`GITHUB_TOKEN`（提升 GHSA 速率限制）、`NVD_API_KEY`（提升 NVD 速率限制）、`SITE_URL`（RSS 中的站点链接）。

## 部署

```bash
npx vercel --prod
```

Vercel 会自动识别 Next.js，无需额外配置。

## 版本说明

早期版本采用「Vercel Cron 每日采集 → OpenRouter LLM 生成中英双语日报 → Upstash Redis 存储 → 企业微信群机器人推送」的流水线，
依赖付费 LLM 与外部存储密钥。当前公开 Demo 版本移除了这些依赖，改为免密钥实时采集 + 规则引擎摘要，便于任何人直接体验。

## 声明

本项目只读取公开的漏洞情报与新闻源，不对任何目标发起扫描或利用。情报仅供防御研究与补丁优先级参考。
