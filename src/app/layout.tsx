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
        <meta httpEquiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' blob: https://cdnjs.cloudflare.com https://api.deepseek.com https://api.moonshot.cn https://ark.cn-beijing.volces.com https://dashscope.aliyuncs.com https://open.bigmodel.cn; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: https://api.qrserver.com; connect-src 'self' https://schedule-api.boluomate.com https://api.deepseek.com https://api.moonshot.cn https://ark.cn-beijing.volces.com https://dashscope.aliyuncs.com https://open.bigmodel.cn https://api.resend.com; font-src 'self'; media-src 'self';" />
      </head>
      <body className="min-h-screen bg-[#F7F5F2]">
        {children}
      </body>
    </html>
  );
}
