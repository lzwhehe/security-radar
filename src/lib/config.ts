import fs from "node:fs";
import path from "node:path";
import YAML from "yaml";

export interface NewsFeed {
  name: string;
  url: string;
  lang?: "zh" | "en";
}

export interface AppConfig {
  cve: {
    min_cvss: number;
    lookback_hours: number;
    max_items: number;
  };
  focus_keywords: string[];
  news_feeds: NewsFeed[];
  limits: {
    news_max: number;
    ghsa_max: number;
    kev_max: number;
    cn_max: number;
  };
}

const DEFAULT_CONFIG: AppConfig = {
  cve: { min_cvss: 7.0, lookback_hours: 36, max_items: 40 },
  focus_keywords: [
    "microsoft",
    "windows",
    "linux",
    "cisco",
    "fortinet",
    "palo alto",
    "vmware",
    "apache",
    "openssl",
    "kubernetes",
    "docker",
    "chrome",
    "android",
    "ios",
  ],
  news_feeds: [
    { name: "安全客", url: "https://api.anquanke.com/data/v1/rss", lang: "zh" },
    { name: "先知社区", url: "https://xz.aliyun.com/feed", lang: "zh" },
    { name: "Seebug Paper", url: "https://paper.seebug.org/rss/", lang: "zh" },
    { name: "Krebs on Security", url: "https://krebsonsecurity.com/feed/", lang: "en" },
    { name: "Schneier on Security", url: "https://www.schneier.com/feed/atom/", lang: "en" },
    { name: "The Hacker News", url: "https://feeds.feedburner.com/TheHackersNews", lang: "en" },
    { name: "BleepingComputer", url: "https://www.bleepingcomputer.com/feed/", lang: "en" },
  ],
  limits: { news_max: 30, ghsa_max: 25, kev_max: 20, cn_max: 15 },
};

let cached: AppConfig | null = null;

export function loadConfig(): AppConfig {
  if (cached) return cached;
  try {
    const p = path.join(process.cwd(), "config.yml");
    if (fs.existsSync(p)) {
      const raw = fs.readFileSync(p, "utf8");
      const parsed = YAML.parse(raw) as Partial<AppConfig>;
      cached = {
        cve: { ...DEFAULT_CONFIG.cve, ...parsed.cve },
        focus_keywords: parsed.focus_keywords ?? DEFAULT_CONFIG.focus_keywords,
        news_feeds: parsed.news_feeds ?? DEFAULT_CONFIG.news_feeds,
        limits: { ...DEFAULT_CONFIG.limits, ...parsed.limits },
      };
      return cached;
    }
  } catch (err) {
    console.warn("[config] 解析 config.yml 失败，使用默认配置:", err);
  }
  cached = DEFAULT_CONFIG;
  return cached;
}
