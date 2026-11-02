import nextPWA from 'next-pwa';

const withPWA = nextPWA({
  dest: 'public',
  register: true,
  skipWaiting: true,
  disable: process.env.NODE_ENV === 'development',
  buildExcludes: [/favicon\.ico$/],
});

/** @type {import('next').NextConfig} */
const nextConfig = withPWA({
  output: 'export',
  // dev 和 build 不共用同一个产物目录。
  // 共用的话，`next dev` 会把静态导出产物（dist/）冲掉 ——
  // 沙盒那个静态预览服务直接 404，而且没法一边跑 dev 一边验证生产构建。
  distDir: process.env.NODE_ENV === 'development' ? '.next-dev' : 'dist',
  images: { unoptimized: true },
  // Cloudflare Pages 配置
  env: {
    NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL || 'https://schedule-api.boluomate.com',
  },
});

export default nextConfig;
