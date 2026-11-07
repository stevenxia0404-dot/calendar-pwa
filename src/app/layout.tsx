import type { Metadata, Viewport } from 'next';
import ViewportSync from '@/components/ViewportSync';
import './globals.css';

export const metadata: Metadata = {
  title: '菠萝日程',
  description: '语音智能日程管理 · 多设备自动同步',
  manifest: '/manifest.json',
  icons: { icon: '/favicon.ico', apple: '/apple-touch-icon.png' },
};

export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
  maximumScale: 1,
  userScalable: false,
  themeColor: '#F7F5F2',
  /**
   * viewport-fit=cover —— 少了这一行，iOS 会把网页**限制在安全区内**
   * （状态栏和 home indicator 之间），后果有三条：
   *
   *   1. 壁纸只铺安全区，顶部状态栏那一条露出系统默认背景（白条）
   *   2. 网页底边正好在 home indicator 上沿，底部输入胶囊被切掉两个角
   *   3. env(safe-area-inset-*) 返回 0 → --sat/--sab 全是 0
   *      （内容本来就在安全区内，就不需要再留了）
   *
   * 加上之后：网页铺满整屏，env() 返回真实值（13 Pro Max 是 47 / 34），
   * 顶栏被 pt-[calc(var(--sat)+...)] 推下来、输入区被 pb-[var(--sab)] 推上去。
   *
   * 为什么开发期的设备画布看不出来：iframe 里 env() 恒为 0，
   * 画布是**手动注入** --sat/--sab 来模拟的 —— 数值对了，
   * 但「没有 cover 时网页被限制在安全区内」这个行为差异没法模拟。
   * 这个 bug 是靠真机截图才发现的。
   */
  viewportFit: 'cover',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="zh-CN">
      <head>
        {/* CSP：只放行真正会用到的源。
            static.cloudflareinsights.com 是 Cloudflare Pages 自带的访客分析
            （开启 Web Analytics 时由边缘注入）。放行它是为了控制台不报违规 ——
            排查问题时红色警告比分析数据更碍事。
            不想要这个统计，去 Cloudflare Dashboard 关掉该 Pages 项目的
            Web Analytics 即可，页面照常工作。 */}
        <meta httpEquiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://static.cloudflareinsights.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: https://api.qrserver.com; connect-src 'self' https://schedule-api.boluomate.com http://192.168.1.27:8787; font-src 'self'; media-src 'self';" />
      </head>
      {/* 原来这里有 min-h-screen（min-height:100vh）——
          **必须去掉**。iOS 上 100vh 是「大视口」（地址栏收起时算的），
          比用户真正看得见的高度高出一截，min-height 会把 body 撑高，
          文档就比视口高 → 手指能滑动页面。

          现在高度由 globals.css 的 html/body { height:100% } + JS 写入的
          --app-vh（= visualViewport.height）共同决定。 */}
      <body className="bg-[#F7F5F2]">
        <ViewportSync />
        {children}
      </body>
    </html>
  );
}
