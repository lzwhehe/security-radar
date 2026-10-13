# 🛡️ 网络安全雷达 · Security Radar

**在线 Demo：<https://agentradar-eight.vercel.app>**（打开即看，无需登录）

实时网络安全情报看板：聚合 **NVD 高危 CVE、GitHub Advisory、CISA KEV（在野利用）与主流安全媒体 RSS**，
用可解释的规则引擎为每条情报打分，给出「今日要点」与「优先处置 Top N」，并提供 JSON API 与 RSS 订阅。

全部数据源都是公开免费接口，**部署不需要任何 API Key、数据库或付费服务**。

## 功能

| 功能 | 说明 |
| --- | --- |
| 多源采集 | NVD CVE API 2.0（近 36h 更新、CVSS ≥ 7）、GitHub Advisory、CISA KEV、**长亭漏洞库（中文 + 修复建议）**、中英文安全资讯（安全客、先知社区、Seebug Paper、Krebs、Schneier 等） |
| 增强信号 | **FIRST EPSS** 未来 30 天被利用概率与百分位；**PoC-in-GitHub** 公开 PoC 数量与 star；**KEV 修复截止倒计时**与勒索软件标记 |
| 跨源关联 | 从结构化字段与正文中提取 CVE 编号，标出被多个情报源同时报道的漏洞（多源印证） |
| 规则引擎打分 | 在野利用 > 勒索关联 > 严重度 > EPSS > 公开 PoC > 多源印证 > 关注厂商 > 新鲜度，每条都给出打分理由 |
| 今日要点 | 自动生成：KEV 新增与修复截止、已有公开 PoC 的漏洞、EPSS 前 1%、严重 CVE、中文漏洞库、高频厂商、资讯头条 |
| CVE 详情抽屉 | 描述、CWE、受影响产品、参考链接、**CISA SSVC 判定与处置建议**（立即处置 / 重点关注 / 跟踪）、PoC 列表、中文修复建议 |
| 交互看板 | 按来源分栏、组合过滤（在野利用 / 有 PoC / EPSS ≥ 10% / 勒索 / 近 7 天）、搜索、按优先级 / EPSS / 时间排序 |
| 关注资产 | 厂商 / 产品关键词存在浏览器本地，命中条目置顶高亮；可用 `?watch=fortinet,gitlab` 链接分享 |
| 导出与接口 | 一键导出当前筛选结果为 CSV；`GET /api/intel` 完整快照、`GET /api/cve/{id}` 单个 CVE 详情、`/feed.xml` RSS |
| 数据源健康 | 每个源 / 每个 RSS / 每项增强数据的状态、条数、耗时与错误原因，单源失败自动降级 |

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

可选环境变量（不填也能运行）：`GITHUB_TOKEN`（提升 GHSA 速率限制）、`NVD_API_KEY`（提升 NVD 速率限制）、`SITE_URL`（RSS 中的站点链接）、`BASE_PATH`（子路径部署，如 `/radar`）、`NEWS_SKIP`（逗号分隔的资讯源名称，跳过当前网络访问不了的源）、`POC_BASE`（PoC-in-GitHub 镜像地址，默认 jsDelivr）。

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
