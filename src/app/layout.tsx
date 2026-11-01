import type { Metadata, Viewport } from 'next';
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
        <meta httpEquiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://static.cloudflareinsights.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: https://api.qrserver.com; connect-src 'self' https://schedule-api.boluomate.com; font-src 'self'; media-src 'self';" />
      </head>
      <body className="min-h-screen bg-[#F7F5F2]">
        {children}
      </body>
    </html>
  );
}
