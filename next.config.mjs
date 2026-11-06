import nextPWA from 'next-pwa';

const withPWA = nextPWA({
  dest: 'public',
  register: true,
  skipWaiting: true,
  disable: process.env.NODE_ENV === 'development',
  buildExcludes: [/favicon\.ico$/],
});

// 生产 API 的真实地址。
// dev 时它只作为「代理目标」用，浏览器不会直接访问它。
const API_ORIGIN = process.env.NEXT_PUBLIC_API_URL || 'https://schedule-api.boluomate.com';

const isDev = process.env.NODE_ENV === 'development';

/** @type {import('next').NextConfig} */
const nextConfig = withPWA({
  output: 'export',
  // dev 和 build 不共用同一个产物目录。
  // 共用的话，`next dev` 会把静态导出产物（dist/）冲掉 ——
  // 沙盒那个静态预览服务直接 404，而且没法一边跑 dev 一边验证生产构建。
  distDir: isDev ? '.next-dev' : 'dist',
  images: { unoptimized: true },
  // Cloudflare Pages 配置
  env: {
    // dev 下用同源相对路径 /api，由 dev server 反向代理到生产 API。
    //
    // 为什么不用直连：直连会撞 CORS。白名单里原本只有 http://localhost:3000，
    // 而预览面板和真机用的是 http://127.0.0.1:3000 / http://192.168.x.x:3000 ——
    // 浏览器看到 Access-Control-Allow-Origin 对不上，直接把响应丢掉，
    // JS 侧只看到一句 "Failed to fetch"，连错误原因都读不到。
    //
    // 走同源代理后，浏览器只跟 dev server 说话，根本不产生跨域请求：
    // localhost / 127.0.0.1 / 局域网 IP 三种访问方式一视同仁。
    NEXT_PUBLIC_API_URL: isDev ? '/api' : API_ORIGIN,
  },
  // output: 'export' 不支持 rewrites（静态导出没有服务端可以转发），
  // 所以这个配置只在 dev 下加。生产构建里 rewrites 是 undefined。
  ...(isDev
    ? {
        rewrites: () => [
          // dev-frame 的「发给我」通道 —— 指向本机的标注收件服务。
          //
          // 为什么不能直接 fetch('http://127.0.0.1:8787/...')：
          // 这台机器设了 http_proxy，浏览器会把 127.0.0.1 也交给代理，
          // 代理不转 localhost → fetch 直接 "Failed to fetch"（实测，localhost 也一样）。
          // 走同源代理后，浏览器只跟 dev server 说话，代理在服务端绕开。
          //
          // 这条必须排在通用规则**前面** —— 先匹配先生效。
          {
            source: '/api/dev-marks',
            destination: 'http://127.0.0.1:8787/marks',
          },
          {
            source: '/api/:path*',
            destination: `${API_ORIGIN}/:path*`,
          },
        ],
      }
    : {}),
});

export default nextConfig;
