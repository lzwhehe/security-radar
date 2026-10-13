import type { SourceResult } from "../types";
import { fetchNvd } from "./nvd";
import { fetchGhsa } from "./ghsa";
import { fetchKev } from "./kev";
import { fetchChaitin } from "./chaitin";
import { fetchNews } from "./news";

/** 记录每个数据源的耗时，供「数据源健康」面板展示 */
async function timed(fn: () => Promise<SourceResult>): Promise<SourceResult> {
  const started = Date.now();
  const result = await fn();
  return { ...result, ms: Date.now() - started };
}

export async function collectAll(): Promise<SourceResult[]> {
  const results = await Promise.all([
    timed(fetchNvd),
    timed(fetchGhsa),
    timed(fetchKev),
    timed(fetchChaitin),
    timed(fetchNews),
  ]);
  for (const r of results) {
    console.log(
      `[source:${r.source}] ok=${r.ok} items=${r.items.length} ms=${r.ms}${r.error ? ` error=${r.error}` : ""}`,
    );
  }
  return results;
}
