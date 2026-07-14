import nextPWA from 'next-pwa';

const withPWA = nextPWA({
  dest: 'public',
  register: true,
  skipWaiting: true,
  disable: process.env.NODE_ENV === 'development',
});

/** @type {import('next').NextConfig} */
const nextConfig = withPWA({
  output: 'export',
  distDir: 'dist',
  images: { unoptimized: true },
  // Cloudflare Pages 配置
  env: {
    NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL || 'https://schedule-api.boluomate.com',
  },
});

export default nextConfig;
