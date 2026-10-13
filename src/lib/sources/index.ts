import type { SourceResult } from "../types";
import { fetchNvd } from "./nvd";
import { fetchGhsa } from "./ghsa";
import { fetchKev } from "./kev";
import { fetchNews } from "./news";

export async function collectAll(): Promise<SourceResult[]> {
  const results = await Promise.all([fetchNvd(), fetchGhsa(), fetchKev(), fetchNews()]);
  for (const r of results) {
    console.log(
      `[source:${r.source}] ok=${r.ok} items=${r.items.length}${r.error ? ` error=${r.error}` : ""}`,
    );
  }
  return results;
}
