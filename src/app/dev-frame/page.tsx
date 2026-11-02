'use client';

// 开发期设备画布 —— 只在 next dev 里有意义
//
// 为什么要它：WorkBuddy 的预览面板是窄的（<768px），只能看到移动版。
// 但「这个按钮在 iPhone 14 Pro Max 上会不会太挤」「iPad 上会不会太空」
// 这些问题，只有在真机尺寸下才看得出来。
//
// 做法：把应用装进一个指定尺寸的 iframe。
// iframe 内部视口 = 指定尺寸 → Tailwind 的 md: 断点真按那个宽度算，
// 不是把移动版硬掰一下（那样 CSS 媒体查询和 JS 里的宽度判断会打架）。
//
// 尺寸数据用真机的 CSS 像素视口（竖屏），
// 底部安全区按有无 home indicator 给值 ——
// iframe 里 env(safe-area-inset-bottom) 恒为 0，
// 所以靠注入 --sab 变量来模拟（app 那边已改成用 var(--sab)）。

import { useCallback, useEffect, useRef, useState } from 'react';

type Notch = 'none' | 'notch' | 'island';

interface Device {
  id: string;
  label: string;
  group: 'iPhone' | 'iPad';
  w: number;
  h: number;
  /** 底部安全区（home indicator / 手势条） */
  sab: number;
  notch: Notch;
  /** 屏幕圆角 */
  radius: number;
}

/** 真机 CSS 像素视口（竖屏） */
const DEVICES: Device[] = [
  { id: 'se3', label: 'iPhone SE (3代)', group: 'iPhone', w: 375, h: 667, sab: 0, notch: 'none', radius: 0 },
  { id: 'ip13mini', label: 'iPhone 13 mini', group: 'iPhone', w: 375, h: 812, sab: 34, notch: 'notch', radius: 44 },
  { id: 'ip14', label: 'iPhone 14', group: 'iPhone', w: 390, h: 844, sab: 34, notch: 'notch', radius: 47 },
  { id: 'ip14pm', label: 'iPhone 14 Pro Max', group: 'iPhone', w: 428, h: 926, sab: 34, notch: 'island', radius: 55 },
  { id: 'ip15plus', label: 'iPhone 15 Plus', group: 'iPhone', w: 430, h: 932, sab: 34, notch: 'island', radius: 55 },
  { id: 'ip16', label: 'iPhone 16', group: 'iPhone', w: 393, h: 852, sab: 34, notch: 'island', radius: 50 },
  { id: 'ip16pm', label: 'iPhone 16 Pro Max', group: 'iPhone', w: 440, h: 956, sab: 34, notch: 'island', radius: 55 },
  { id: 'ipadmini', label: 'iPad mini (6代)', group: 'iPad', w: 744, h: 1133, sab: 0, notch: 'none', radius: 21 },
  { id: 'ipad109', label: 'iPad (10.9")', group: 'iPad', w: 820, h: 1180, sab: 0, notch: 'none', radius: 18 },
  { id: 'ipadair11', label: 'iPad Air 11"', group: 'iPad', w: 820, h: 1180, sab: 0, notch: 'none', radius: 18 },
  { id: 'ipadpro11', label: 'iPad Pro 11"', group: 'iPad', w: 834, h: 1210, sab: 0, notch: 'none', radius: 18 },
  { id: 'ipadpro13', label: 'iPad Pro 13"', group: 'iPad', w: 1024, h: 1366, sab: 0, notch: 'none', radius: 18 },
];

export default function DevFrame() {
  const [deviceId, setDeviceId] = useState('ip16');
  const [landscape, setLandscape] = useState(false);
  const [customW, setCustomW] = useState(0);
  const [customH, setCustomH] = useState(0);
  const [scale, setScale] = useState(1);
  const [dev, setDev] = useState(true);

  const iframeRef = useRef<HTMLIFrameElement | null>(null);
  const boxRef = useRef<HTMLDivElement | null>(null);

  const device = DEVICES.find(d => d.id === deviceId) || DEVICES[0];
  const w = customW > 0 ? customW : (landscape ? device.h : device.w);
  const h = customH > 0 ? customH : (landscape ? device.w : device.h);
  const sab = customW > 0 ? 0 : device.sab;
  const notch = customW > 0 ? 'none' : device.notch;
  const radius = customW > 0 ? 0 : device.radius;

  // ---------- 安全区注入 ----------
  // iframe 里 env(safe-area-inset-bottom) 恒为 0，
  // 覆盖 --sab 就能模拟出「真 iPhone 底部留 34px」的效果。
  const injectSafeArea = useCallback(() => {
    const doc = iframeRef.current?.contentDocument;
    if (!doc?.head) return;
    let s = doc.getElementById('__sab') as HTMLStyleElement | null;
    if (!s) {
      s = doc.createElement('style');
      s.id = '__sab';
      doc.head.appendChild(s);
    }
    s.textContent = `:root{--sab:${sab}px}`;
  }, [sab]);

  useEffect(() => {
    const q = new URLSearchParams(window.location.search);
    const qd = q.get('d');
    if (qd && DEVICES.some(x => x.id === qd)) setDeviceId(qd);
    const qw = Number(q.get('w'));
    const qh = Number(q.get('h'));
    if (qw > 200) setCustomW(qw);
    if (qh > 200) setCustomH(qh);
    setDev(process.env.NODE_ENV === 'development');
  }, []);

  useEffect(() => { injectSafeArea(); }, [injectSafeArea]);

  // iframe 重新加载后要再注入一次
  useEffect(() => {
    const f = iframeRef.current;
    if (!f) return;
    const onLoad = () => { injectSafeArea(); setTimeout(injectSafeArea, 400); };
    f.addEventListener('load', onLoad);
    return () => f.removeEventListener('load', onLoad);
  }, [injectSafeArea]);

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
    const t = setTimeout(fit, 120);
    return () => { window.removeEventListener('resize', fit); clearTimeout(t); };
  }, [w]);

  if (!dev) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#F7F5F2] text-[#A0A0A0] text-sm">
        这个页面只在开发环境里有意义
      </div>
    );
  }

  const iphone = device.group === 'iPhone';

  return (
    <div className="min-h-screen bg-[#E8E4DF] flex flex-col">
      {/* 工具条 */}
      <div className="shrink-0 bg-white border-b border-[#D9D4CF] px-3 py-2 flex items-center gap-2 flex-wrap">
        <span className="text-xs font-semibold text-[#1C1C1C]">设备</span>

        <select
          value={customW > 0 ? 'custom' : deviceId}
          onChange={e => {
            const v = e.target.value;
            if (v === 'custom') { setCustomW(w); setCustomH(h); }
            else { setDeviceId(v); setCustomW(0); setCustomH(0); }
          }}
          className="px-1.5 py-1 rounded border border-[#E8E4DF] text-[11px] bg-white"
        >
          <optgroup label="iPhone">
            {DEVICES.filter(d => d.group === 'iPhone').map(d => (
              <option key={d.id} value={d.id}>{d.label} · {d.w}×{d.h}</option>
            ))}
          </optgroup>
          <optgroup label="iPad">
            {DEVICES.filter(d => d.group === 'iPad').map(d => (
              <option key={d.id} value={d.id}>{d.label} · {d.w}×{d.h}</option>
            ))}
          </optgroup>
          <option value="custom">自定义 · {w}×{h}</option>
        </select>

        <button
          onClick={() => { setLandscape(v => !v); setCustomW(0); setCustomH(0); }}
          className="px-2 py-1 rounded text-[11px] bg-[#F3F1ED] text-[#5C5C5C] hover:bg-[#E8E4DF]"
        >
          {landscape ? '竖屏' : '横屏'}
        </button>

        <input
          type="number" placeholder="宽"
          value={customW || ''}
          onChange={e => setCustomW(Number(e.target.value) || 0)}
          className="w-16 px-1.5 py-1 rounded border border-[#E8E4DF] text-[11px] font-mono"
        />
        <input
          type="number" placeholder="高"
          value={customH || ''}
          onChange={e => setCustomH(Number(e.target.value) || 0)}
          className="w-16 px-1.5 py-1 rounded border border-[#E8E4DF] text-[11px] font-mono"
        />

        <span className="text-[11px] text-[#A0A0A0]">
          视口 {w}×{h} · 安全区底 {sab}px · 显示 {Math.round(scale * 100)}%
        </span>
        <span className="text-[11px] text-[#A0A0A0] ml-auto">
          画面里按 Alt+I 开标注，点完直接粘给我
        </span>
      </div>

      {/* 画布 */}
      <div ref={boxRef} className="flex-1 overflow-auto p-2">
        <div
          style={{
            width: w * scale,
            height: h * scale,
            overflow: 'hidden',
            borderRadius: radius * scale,
            boxShadow: '0 6px 32px rgba(0,0,0,0.22)',
          }}
        >
          <div
            style={{
              width: w, height: h,
              transform: `scale(${scale})`,
              transformOrigin: 'top left',
              position: 'relative',
            }}
          >
            <iframe
              ref={iframeRef}
              src="/"
              title="设备画布"
              onLoad={() => { injectSafeArea(); setTimeout(injectSafeArea, 400); }}
              style={{ width: '100%', height: '100%', border: 0, display: 'block' }}
            />

            {/* 设备装饰层（近似画法，只为判断元素会不会压到刘海/手势条） */}
            <div className="absolute inset-0 pointer-events-none">
              {notch === 'notch' && (
                <div className="absolute top-0 left-1/2 -translate-x-1/2 bg-black"
                  style={{ width: 162, height: 32, borderRadius: '0 0 18px 18px' }} />
              )}
              {notch === 'island' && (
                <div className="absolute top-2 left-1/2 -translate-x-1/2 bg-black"
                  style={{ width: 126, height: 37, borderRadius: 20 }} />
              )}
              {sab > 0 && (
                <div className="absolute bottom-1.5 left-1/2 -translate-x-1/2 bg-black/35"
                  style={{ width: 140, height: 5, borderRadius: 3 }} />
              )}
              {/* 屏幕圆角遮罩：让直角内容看起来像被屏幕裁过 */}
              {radius > 0 && (
                <div className="absolute inset-0" style={{
                  borderRadius: radius,
                  boxShadow: `inset 0 0 0 1px rgba(0,0,0,0.08)`,
                }} />
              )}
              {iphone && (
                <div className="absolute top-1 left-1/2 -translate-x-1/2 text-[9px] text-black/40 font-mono">
                  {device.label}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
