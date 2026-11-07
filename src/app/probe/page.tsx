// 真机视口探针 —— 部署到生产站的一个临时页面。
//
// 用法：手机浏览器打开 https://schedule.boluomate.com/probe
// 页面会自动采集所有关键视口数据，POST 到局域网收件服务。
// 我这边收到文件就能直接读到真机的真实数值 —— 不用再看录屏。
//
// **这是临时诊断页，验完就删。**

'use client';

import { useEffect, useState } from 'react';

/** 局域网收件服务（手机同 WiFi 可直连） */
const RECEIVER = 'http://192.168.1.27:8787/marks';

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
  mainH: number;
  mainTop: number;
  canScroll: boolean;
  scrollY: number;
  /** 100vh / 100dvh 各是多少 —— 用探针元素量出来 */
  vh: number;
  dvh: number;
};

export default function ProbePage() {
  const [data, setData] = useState<Probe | null>(null);
  const [sent, setSent] = useState<string>('');

  useEffect(() => {
    const collect = (): Probe => {
      const de = document.documentElement;
      const body = document.body;
      const vv = window.visualViewport;
      const main = document.querySelector('main');

      // 量 100vh / 100dvh 各等于多少像素
      const measure = (unit: string) => {
        const el = document.createElement('div');
        el.style.cssText = `position:fixed;visibility:hidden;height:100${unit};top:0;left:0;`;
        document.body.appendChild(el);
        const h = el.getBoundingClientRect().height;
        el.remove();
        return Math.round(h);
      };

      const cs = getComputedStyle(de);
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
        mainH: main ? Math.round(main.getBoundingClientRect().height) : -1,
        mainTop: main ? Math.round(main.getBoundingClientRect().top) : -1,
        canScroll: false,
        scrollY: window.scrollY,
        vh: measure('vh'),
        dvh: measure('dvh'),
      };
    };

    const run = async () => {
      const p = collect();
      // 试试能不能滚 —— 这是最直接的证据
      window.scrollTo(0, 400);
      p.canScroll = window.scrollY > 0;
      p.scrollY = window.scrollY;
      window.scrollTo(0, 0);
      setData(p);

      try {
        await fetch(RECEIVER, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify([{ n: 1, component: 'ViewportProbe', text: '真机视口探测', ...p }]),
        });
        setSent('已发送 ✓');
      } catch (e) {
        setSent('发送失败：' + (e as Error).message);
      }
    };

    run();
    // 键盘弹出/地址栏收放会改变数值，过一会儿再采一次
    const t = setTimeout(run, 1500);
    return () => clearTimeout(t);
  }, []);

  return (
    <div className="p-4 text-xs font-mono leading-relaxed">
      <h1 className="text-base font-bold mb-3">真机视口探针</h1>
      {data && (
        <table className="w-full border-collapse">
          <tbody>
            {Object.entries(data).map(([k, v]) => (
              <tr key={k} className="border-b border-[#E8E4DF]">
                <td className="py-1 pr-3 text-[#8A8A8A] w-40 align-top">{k}</td>
                <td className="py-1 break-all">{String(v)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <p className="mt-4 text-[#ED6A3B] font-bold">{sent}</p>
      <p className="mt-2 text-[#8A8A8A]">
        关键判据：<br />
        · canScroll = false 才算修好（现在能不能滑）<br />
        · htmlOverflow / bodyOverflow 应当是 0<br />
        · visualH 应当等于 mainH（可视区 = 应用外壳）<br />
        · vh 与 dvh 若大于 visualH，就是 iOS 撑高的元凶
      </p>
    </div>
  );
}
