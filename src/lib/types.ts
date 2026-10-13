export type SourceKind = "cve" | "ghsa" | "kev" | "news";

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
}

export interface SourceResult {
  source: SourceKind;
  items: RawItem[];
  ok: boolean;
  error?: string;
  /** 过滤前的原始条数（如 KEV 目录总量、NVD 窗口内更新数） */
  total?: number;
}

/** 规则引擎为单条情报打出的优先级 */
export interface ScoredItem extends RawItem {
  priority: number;
  reasons: string[];
  /** 同一 CVE 出现在哪些来源 */
  seenIn: SourceKind[];
}

export interface BriefingPoint {
  level: "critical" | "high" | "info";
  text: string;
}

export interface IntelSnapshot {
  fetchedAt: string;
  sources: { source: SourceKind; ok: boolean; count: number; total?: number; error?: string }[];
  items: ScoredItem[];
  top: ScoredItem[];
  briefing: BriefingPoint[];
}
