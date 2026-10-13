import { XMLParser } from "fast-xml-parser";
import type { RawItem, SourceResult } from "../types";
import { loadConfig } from "../config";

const parser = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: "@_" });

function stripHtml(s: string): string {
  return s
    .replace(/<[^>]+>/g, " ")
    .replace(/&[a-z]+;/gi, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function asArray<T>(v: T | T[] | undefined): T[] {
  if (!v) return [];
  return Array.isArray(v) ? v : [v];
}

interface FeedItem {
  title?: string | { "#text"?: string };
  link?: string | { "@_href"?: string } | { "@_href"?: string }[];
  description?: string;
  summary?: string;
  content?: string;
  pubDate?: string;
  published?: string;
  updated?: string;
}

function textOf(v: unknown): string {
  if (!v) return "";
  if (typeof v === "string") return v;
  if (typeof v === "object" && "#text" in (v as any)) return String((v as any)["#text"] ?? "");
  return String(v);
}

function linkOf(item: FeedItem): string {
  const l = item.link;
  if (typeof l === "string") return l;
  const arr = asArray(l as any);
  for (const x of arr) {
    if (typeof x === "string") return x;
    if (x && typeof x === "object" && x["@_href"]) return x["@_href"];
  }
  return "";
}

async function fetchFeed(name: string, url: string, max: number): Promise<RawItem[]> {
  const res = await fetch(url, {
    headers: { "User-Agent": "security-radar/1.0", Accept: "application/rss+xml, application/xml" },
    signal: AbortSignal.timeout(20000),
  });
  if (!res.ok) throw new Error(`${name} HTTP ${res.status}`);
  const xml = await res.text();
  const doc = parser.parse(xml);

  // RSS: rss.channel.item ；Atom: feed.entry
  const rssItems = asArray<FeedItem>(doc?.rss?.channel?.item);
  const atomItems = asArray<FeedItem>(doc?.feed?.entry);
  const raw = rssItems.length ? rssItems : atomItems;

  return raw.slice(0, max).map((it, i) => {
    const title = textOf(it.title);
    const body = stripHtml(textOf(it.description) || textOf(it.summary) || textOf(it.content));
    return {
      source: "news" as const,
      sourceName: name,
      id: `${name}-${i}-${linkOf(it)}`.slice(0, 120),
      title,
      url: linkOf(it),
      summary: body.slice(0, 400),
      publishedAt: it.pubDate || it.published || it.updated,
    } satisfies RawItem;
  });
}

export async function fetchNews(): Promise<SourceResult> {
  const cfg = loadConfig();
  const perFeed = Math.max(4, Math.ceil(cfg.limits.news_max / cfg.news_feeds.length));
  const results = await Promise.allSettled(
    cfg.news_feeds.map((f) => fetchFeed(f.name, f.url, perFeed)),
  );

  const items: RawItem[] = [];
  const errors: string[] = [];
  for (const r of results) {
    if (r.status === "fulfilled") items.push(...r.value);
    else errors.push(String(r.reason));
  }

  items.sort((a, b) => {
    const ta = a.publishedAt ? Date.parse(a.publishedAt) : 0;
    const tb = b.publishedAt ? Date.parse(b.publishedAt) : 0;
    return tb - ta;
  });

  return {
    source: "news",
    ok: items.length > 0,
    items: items.slice(0, cfg.limits.news_max),
    error: errors.length ? errors.join("; ") : undefined,
  };
}
