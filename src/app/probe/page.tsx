// 真机视口探针 —— 让手机自己把「眼里的页面尺寸」报回来。
//
// ---------------------------------------------------------------------------
// **为什么要有它**
//
// 模拟器（headless Chrome / iframe）测不出 iOS 的真实视口语义：
//   · 100vh / 100dvh / visualViewport.height 在模拟器里三者全相等，
//     而真机上 100vh 明显偏高 —— 于是模拟器证明不了「能不能滑」
//   · iframe 里 env(safe-area-inset-*) 恒为 0，安全区行为完全模拟不了
//   · iOS 的橡皮筋回弹、键盘弹出导致的视口变化，模拟器一律没有
//
// 所以「用户描述现象」不够，「模拟器实测」也不够 ——
// 必须让**真机自己把数字报回来**。
//
// ---------------------------------------------------------------------------
// **数据怎么回来（这里有个坑）**
//
// 直连本机收件服务（http://<局域网IP>:8787）在生产站上**必然失败**：
// 生产是 HTTPS，目标是 HTTP —— Safari 把它当**混合内容**直接拦掉。
// （查证的结论：WebKit 不遵循 W3C 混合内容规范，
//   连 http://127.0.0.0/8 和 http://localhost 都照样拦，iOS 18 更严。）
//
// 所以走**同源**：POST 到本域的 /api/dev-marks，
// 由 dev server 的 rewrite 服务端转发到本机收件服务。
// 服务端转发不经过浏览器 → 没有混合内容、没有 CORS、没有代理问题。
//
// ⚠️ 因此这个探针**只能在 dev server 上用**（rewrite 只在 dev 生效）。
//    生产站上打开它会 POST 失败 —— 那是预期行为，不是 bug。
//
// ---------------------------------------------------------------------------

'use client';

import { useEffect, useState } from 'react';

/**
 * 生产环境不采集、不发送。
 *
 * 这个探针的数据会 POST 到本机的收件服务 —— 生产站上那条 rewrite 不存在，
 * POST 必然 404。干脆在生产构建里整个不干活：
 * 既不读数据，也不发任何请求。
 */
const IS_DEV = process.env.NODE_ENV === 'development';

/**
 * 要检查的选择器 —— 通过 URL 参数传进来。
 *
 * 例：/probe?main=main&dock=.input-dock
 * 不传就只做通用视口测量（不碰任何项目特定的选择器）。
 */
function readTargets(): { sel: string; label: string }[] {
  if (typeof window === 'undefined') return [];
  const p = new URLSearchParams(window.location.search);
  const out: { sel: string; label: string }[] = [];
  // 通用语法：?t=main:main,.input-dock:输入区  （选择器:标签,选择器:标签）
  const raw = p.get('t');
  if (raw) {
    raw.split(',').forEach(pair => {
      const i = pair.lastIndexOf(':');
      if (i > 0) out.push({ sel: pair.slice(0, i), label: pair.slice(i + 1) });
    });
  }
  return out;
}

type Probe = {
  at: string;
  ua: string;
  innerW: number;
  innerH: number;
  visualH: number | null;
  visualTop: number | null;
  visualScale: number | null;
  docClientH: number;
  docScrollH: number;
  bodyClientH: number;
  bodyScrollH: number;
  bodyOverflow: number;
  htmlOverflow: number;
  appVh: string;
  appKb: string;
  sat: string;
  sab: string;
  canScroll: boolean;
  scrollY: number;
  /** 100vh / 100dvh 各等于多少像素 —— 用探针元素量出来 */
  vh: number;
  dvh: number;
  /** 自定义目标的实测矩形 */
  targets: { label: string; sel: string; found: boolean; x: number; y: number; w: number; h: number }[];
};

export default function ProbePage() {
  const [data, setData] = useState<Probe | null>(null);
  const [sent, setSent] = useState('');

  useEffect(() => {
    if (!IS_DEV) return;
    const collect = (): Probe => {
      const de = document.documentElement;
      const body = document.body;
      const vv = window.visualViewport;
      const cs = getComputedStyle(de);

      // 量 100vh / 100dvh 各等于多少像素。
      // 探针元素必须挂在 body 上 —— 挂在 html 里会被 html 的高度约束影响。
      const measure = (unit: string) => {
        const el = document.createElement('div');
        el.style.cssText = `position:fixed;visibility:hidden;height:100${unit};top:0;left:0;width:0;`;
        document.body.appendChild(el);
        const h = el.getBoundingClientRect().height;
        el.remove();
        return Math.round(h);
      };

      const targets = readTargets().map(t => {
        const el = document.querySelector(t.sel);
        if (!el) return { label: t.label, sel: t.sel, found: false, x: 0, y: 0, w: 0, h: 0 };
        const r = el.getBoundingClientRect();
        return {
          label: t.label, sel: t.sel, found: true,
          x: Math.round(r.x), y: Math.round(r.y),
          w: Math.round(r.width), h: Math.round(r.height),
        };
      });

      return {
        at: new Date().toISOString(),
        ua: navigator.userAgent,
        innerW: window.innerWidth,
        innerH: window.innerHeight,
        visualH: vv ? Math.round(vv.height) : null,
        visualTop: vv ? Math.round(vv.offsetTop) : null,
        visualScale: vv ? vv.scale : null,
        docClientH: de.clientHeight,
        docScrollH: de.scrollHeight,
        bodyClientH: body.clientHeight,
        bodyScrollH: body.scrollHeight,
        bodyOverflow: body.scrollHeight - body.clientHeight,
        htmlOverflow: de.scrollHeight - de.clientHeight,
        appVh: cs.getPropertyValue('--app-vh').trim(),
        appKb: cs.getPropertyValue('--app-kb').trim(),
        sat: cs.getPropertyValue('--sat').trim(),
        sab: cs.getPropertyValue('--sab').trim(),
        canScroll: false,
        scrollY: window.scrollY,
        vh: measure('vh'),
        dvh: measure('dvh'),
        targets,
      };
    };

    const run = async () => {
      const p = collect();

      // 直接试能不能滚 —— 这是最硬的证据，不用人描述
      window.scrollTo(0, 400);
      p.canScroll = window.scrollY > 0;
      p.scrollY = window.scrollY;
      window.scrollTo(0, 0);

      setData(p);

      // 同源 POST —— 由 dev server 的 rewrite 转发到本机收件服务。
      // 不能直连 http://<局域网IP>:8787 —— HTTPS 页面发 HTTP 会被 Safari
      // 当混合内容拦掉（WebKit 不遵循规范，连 localhost 都不放过）。
      try {
        const r = await fetch('/api/dev-marks', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify([{ n: 1, component: 'ViewportProbe', text: '真机视口探测', ...p }]),
        });
        setSent(r.ok ? '已发送 ✓' : '发送失败 HTTP ' + r.status);
      } catch (e) {
        setSent('发送失败：' + (e as Error).message + '（生产站上必然失败，要用 dev server）');
      }
    };

    run();
    // 键盘弹出 / 地址栏收放会改变数值，过一会儿再采一次
    const t = setTimeout(run, 1500);
    return () => clearTimeout(t);
  }, []);

  return (
    <div className="p-4 text-xs font-mono leading-relaxed">
      <h1 className="text-base font-bold mb-3">真机视口探针</h1>
      {!IS_DEV && (
        <p className="text-[#8A8A8A] leading-relaxed">
          生产环境不启用。
          <br />
          这个探针把数据 POST 到本机的收件服务（dev server 的 rewrite 转发），
          <br />
          生产站上没有那条 rewrite，跑不出数据 —— 所以直接不采集。
          <br />
          <br />
          开发期用法：<code>http://&lt;局域网IP&gt;:3000/probe</code>
        </p>
      )}
      {data && (
        <table className="w-full border-collapse">
          <tbody>
            {Object.entries(data).map(([k, v]) => (
              <tr key={k} className="border-b border-[#E8E4DF]">
                <td className="py-1 pr-3 text-[#8A8A8A] w-40 align-top">{k}</td>
                <td className="py-1 break-all">{typeof v === 'object' ? JSON.stringify(v) : String(v)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <p className="mt-4 text-[#ED6A3B] font-bold">{sent}</p>
      <p className="mt-2 text-[#8A8A8A] leading-relaxed">
        关键判据：<br />
        · <b>canScroll = false</b> 才算修好（现在能不能滑）<br />
        · <b>htmlOverflow / bodyOverflow</b> 应当是 0<br />
        · <b>visualH</b> 应当等于 main 的高度（可视区 = 应用外壳）<br />
        · <b>vh / dvh</b> 若大于 visualH，就是 iOS 撑高的元凶<br />
        · <b>sat / sab</b> 非 0 说明安全区生效（PWA 全屏模式）
      </p>
    </div>
  );
}
