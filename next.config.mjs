/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // 子路径部署（如 Nginx 网关下的 /radar）；Vercel 根路径部署时不设置
  basePath: process.env.BASE_PATH || "",
  // 客户端请求 API、页头链接时需要带上子路径前缀
  env: { NEXT_PUBLIC_BASE_PATH: process.env.BASE_PATH || "" },
  // Docker 镜像用 standalone 产物（node server.js），本地 next start / Vercel 不受影响
  ...(process.env.STANDALONE ? { output: "standalone" } : {}),
  // 构建时预渲染需实时请求 NVD 等外部源，放宽单页生成超时
  staticPageGenerationTimeout: 180,
};

export default nextConfig;
