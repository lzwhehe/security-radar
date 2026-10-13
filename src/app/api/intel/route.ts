import { getIntel } from "@/lib/intel";

// 只读 JSON 接口：返回与首页相同的聚合快照
export const dynamic = "force-dynamic"; // 每次请求读共享缓存（unstable_cache）+ CDN s-maxage
export const maxDuration = 60;

export async function GET() {
  const intel = await getIntel();
  return Response.json(intel, {
    headers: { "Cache-Control": "public, s-maxage=1800, stale-while-revalidate=3600" },
  });
}
