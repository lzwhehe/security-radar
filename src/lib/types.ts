export type SourceKind = "cve" | "ghsa" | "kev" | "cn" | "news";

export interface RawItem {
  source: SourceKind;
  sourceName: string;
  id: string;
  title: string;
  url: string;
  /** 简短描述/摘要 */
  summary?: string;
  /** 严重程度，如 CRITICAL/HIGH 或 CVSS 分数文本 */
  severity?: string;
  score?: number;
  /** ISO 时间字符串 */
  publishedAt?: string;
  /** 命中的关注关键词 */
  tags?: string[];
  /** 关联的 CVE 编号（用于跨源关联） */
  cve?: string;
  /** CISA KEV：联邦机构修复截止日（YYYY-MM-DD） */
  dueDate?: string;
  /** CISA KEV：已知被勒索软件活动利用 */
  ransomware?: boolean;
  /** 中文漏洞库：修复建议 */
  fixSteps?: string;
  /** 内容语言 */
  lang?: "zh" | "en";
}

export interface FeedStatus {
  name: string;
  ok: boolean;
  count: number;
  ms: number;
  error?: string;
}

export interface SourceResult {
  source: SourceKind;
  items: RawItem[];
  ok: boolean;
  error?: string;
  /** 过滤前的原始条数（如 KEV 目录总量、NVD 窗口内更新数） */
  total?: number;
  /** 请求耗时（毫秒） */
  ms?: number;
  /** 资讯源：每个 RSS 的状态 */
  feeds?: FeedStatus[];
}

export interface PocInfo {
  /** 公开 PoC 仓库数量 */
  count: number;
  /** 最高 star 数 */
  stars: number;
  top: { name: string; url: string; stars: number }[];
}

/** 规则引擎为单条情报打出的优先级 */
export interface ScoredItem extends RawItem {
  priority: number;
  reasons: string[];
  /** 同一 CVE 出现在哪些来源 */
  seenIn: SourceKind[];
  /** EPSS：未来 30 天被利用的概率（0–1） */
  epss?: number;
  /** EPSS 百分位（0–1） */
  epssPct?: number;
  poc?: PocInfo;
  /** 距 KEV 修复截止日的天数（负数表示已逾期） */
  kevDueDays?: number;
}

export interface BriefingPoint {
  level: "critical" | "high" | "info";
  text: string;
}

export interface SourceStatus {
  source: SourceKind;
  ok: boolean;
  count: number;
  total?: number;
  error?: string;
  ms?: number;
  feeds?: FeedStatus[];
}

export interface EnrichStatus {
  epss: { ok: boolean; count: number; ms: number; error?: string };
  poc: { ok: boolean; checked: number; found: number; ms: number; error?: string };
}

export interface IntelSnapshot {
  fetchedAt: string;
  sources: SourceStatus[];
  enrich: EnrichStatus;
  items: ScoredItem[];
  top: ScoredItem[];
  briefing: BriefingPoint[];
}
