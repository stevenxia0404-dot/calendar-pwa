'use client';

// 开发期桌面画布 —— 只在 next dev 里有意义
//
// 为什么要它：WorkBuddy 的预览面板是窄的（<768px），
// 只能看到移动版布局。而这个应用的桌面版是「周视图 + 明细卡」左右并排，
// 光看移动版改不出桌面版的问题。
//
// 做法：把应用整个装进一个指定宽度的 iframe 里。
// iframe 的内部视口宽度 = 指定宽度 → Tailwind 的 md: 断点真的按桌面算，
// 不是把移动版硬掰一下（那样 CSS 和逻辑会打架）。

import { useEffect, useRef, useState } from 'react';

const PRESETS = [
  { w: 390, h: 844, label: '手机' },
  { w: 768, h: 900, label: '断点' },
  { w: 1280, h: 860, label: '桌面' },
  { w: 1600, h: 900, label: '宽屏' },
];

export default function DevFrame() {
  const [w, setW] = useState(1280);
  const [h, setH] = useState(860);
  const [scale, setScale] = useState(1);
  // 构建期常量 —— 静态导出时这个值会被替换成 false，
  // 导出的 HTML 直接就是「仅开发环境可用」，不会先闪一下画布。
  const [dev] = useState(process.env.NODE_ENV === 'development');
  const boxRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const q = new URLSearchParams(window.location.search);
    const qw = Number(q.get('w'));
    const qh = Number(q.get('h'));
    if (qw > 200) setW(qw);
    if (qh > 200) setH(qh);
  }, []);

  // 缩放：把指定宽度的画面塞进面板，等比缩小
  useEffect(() => {
    const fit = () => {
      const box = boxRef.current;
      if (!box) return;
      const avail = box.clientWidth - 16;
      setScale(Math.min(1, avail / w));
    };
    fit();
    window.addEventListener('resize', fit);
    const t = setTimeout(fit, 100);
    return () => { window.removeEventListener('resize', fit); clearTimeout(t); };
  }, [w]);

  if (!dev) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#F7F5F2] text-[#A0A0A0] text-sm">
        这个页面只在开发环境里有意义
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#E8E4DF] flex flex-col">
      {/* 工具条 */}
      <div className="shrink-0 bg-white border-b border-[#D9D4CF] px-3 py-2 flex items-center gap-2 flex-wrap">
        <span className="text-xs font-semibold text-[#1C1C1C]">画布</span>
        {PRESETS.map(p => (
          <button
            key={p.w}
            onClick={() => { setW(p.w); setH(p.h); }}
            className={`px-2 py-1 rounded text-[11px] ${
              w === p.w ? 'bg-[#ED6A3B] text-white' : 'bg-[#F3F1ED] text-[#5C5C5C] hover:bg-[#E8E4DF]'
            }`}
          >
            {p.label} {p.w}
          </button>
        ))}
        <input
          type="number"
          value={w}
          onChange={e => setW(Math.max(320, Number(e.target.value) || 1280))}
          className="w-16 px-1.5 py-1 rounded border border-[#E8E4DF] text-[11px] font-mono"
        />
        <span className="text-[11px] text-[#A0A0A0]">
          实际视口 {w}×{h} · 显示比例 {Math.round(scale * 100)}%
        </span>
        <span className="text-[11px] text-[#A0A0A0] ml-auto">
          在画面里按 Alt+I 开标注，点完直接粘给我
        </span>
      </div>

      {/* 画布 */}
      <div ref={boxRef} className="flex-1 overflow-auto p-2">
        <div
          style={{
            width: w * scale,
            height: h * scale,
            overflow: 'hidden',
            borderRadius: 8,
            boxShadow: '0 4px 24px rgba(0,0,0,0.15)',
          }}
        >
          <iframe
            src="/"
            title="画布"
            style={{
              width: w,
              height: h,
              transform: `scale(${scale})`,
              transformOrigin: 'top left',
              border: 0,
            }}
          />
        </div>
      </div>
    </div>
  );
}
