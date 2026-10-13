/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // 构建时预渲染需实时请求 NVD 等外部源，放宽单页生成超时
  staticPageGenerationTimeout: 180,
};

export default nextConfig;
