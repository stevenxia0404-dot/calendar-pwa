'use client';

// 开发期设备画布 —— 只在 next dev 里有意义
//
// 为什么要它：WorkBuddy 的预览面板是窄的（<768px），只能看到移动版。
// 但「这个按钮在 iPhone 14 Pro Max 上会不会太挤」「iPad 上会不会太空」
// 这些问题，只有在真机尺寸下才看得出来。
//
// 做法：把应用装进一个指定尺寸的 iframe。
// iframe 内部视口 = 指定尺寸 → Tailwind 的 md: 断点真按那个宽度算，
// 不是把移动版硬掰一下（那样 CSS 媒体查询和 isNarrow 逻辑会打架）。
//
// 尺寸数据用真机的 CSS 像素视口（竖屏），
// 安全区按机型给值 —— iframe 里 env(safe-area-inset-*) 恒为 0，
// 所以靠注入 --sat / --sab 变量来模拟（app 那边已改成用 var()）。
//
// 状态栏分两种情况（这决定布局对不对）：
//   有刘海/灵动岛 → 状态栏**盖在内容上**，app 要自己留出 --sat
//   无刘海（SE）/ iPad → 状态栏是独立一条，网页从它下面开始（--sat = 0）

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
  /** 顶部安全区：状态栏是否压在内容上 */
  sat: number;
  /** 状态栏自身的高度（画出来的那条） */
  statusH: number;
  notch: Notch;
  /** 屏幕圆角 */
  radius: number;
}

/**
 * 真机 CSS 像素视口（竖屏）。
 *
 * 同一档尺寸的机型合并成一条（尺寸一样就没必要分开选），
 * 标签里把共用的机型都列出来，省得他想找 13 Pro Max 却找不到。
 */
const DEVICES: Device[] = [
  // ---- iPhone ----
  { id: 'se3', label: 'iPhone SE (3代)', group: 'iPhone', w: 375, h: 667, sab: 0, sat: 0, statusH: 20, notch: 'none', radius: 0 },
  { id: 'ip13mini', label: 'iPhone 13 mini', group: 'iPhone', w: 375, h: 812, sab: 34, sat: 44, statusH: 44, notch: 'notch', radius: 44 },
  { id: 'ip13', label: 'iPhone 13 / 13 Pro / 14', group: 'iPhone', w: 390, h: 844, sab: 34, sat: 47, statusH: 47, notch: 'notch', radius: 47 },
  { id: 'ip13pm', label: 'iPhone 13 Pro Max / 14 Plus / 14 Pro Max', group: 'iPhone', w: 428, h: 926, sab: 34, sat: 47, statusH: 47, notch: 'notch', radius: 55 },
  { id: 'ip14pro', label: 'iPhone 14 Pro / 15 / 16', group: 'iPhone', w: 393, h: 852, sab: 34, sat: 59, statusH: 59, notch: 'island', radius: 50 },
  { id: 'ip15plus', label: 'iPhone 15 Plus / 16 Plus', group: 'iPhone', w: 430, h: 932, sab: 34, sat: 59, statusH: 59, notch: 'island', radius: 55 },
  { id: 'ip15pro', label: 'iPhone 15 Pro / 16 Pro', group: 'iPhone', w: 402, h: 874, sab: 34, sat: 62, statusH: 62, notch: 'island', radius: 52 },
  { id: 'ip16pm', label: 'iPhone 16 Pro Max', group: 'iPhone', w: 440, h: 956, sab: 34, sat: 62, statusH: 62, notch: 'island', radius: 55 },

  // ---- iPad ----
  { id: 'ipadmini', label: 'iPad mini (6代)', group: 'iPad', w: 744, h: 1133, sab: 0, sat: 0, statusH: 24, notch: 'none', radius: 21 },
  { id: 'ipad109', label: 'iPad (10.9") / Air 11"', group: 'iPad', w: 820, h: 1180, sab: 0, sat: 0, statusH: 24, notch: 'none', radius: 18 },
  { id: 'ipadpro11', label: 'iPad Pro 11"', group: 'iPad', w: 834, h: 1210, sab: 0, sat: 0, statusH: 24, notch: 'none', radius: 18 },
  { id: 'ipadpro13', label: 'iPad Pro 13"', group: 'iPad', w: 1024, h: 1366, sab: 0, sat: 0, statusH: 24, notch: 'none', radius: 18 },
];

export default function DevFrame() {
  const [deviceId, setDeviceId] = useState('ip14pro');
  const [landscape, setLandscape] = useState(false);
  const [customW, setCustomW] = useState(0);
  const [customH, setCustomH] = useState(0);
  const [scale, setScale] = useState(1);
  /** 1:1 真实像素 —— 看细节用，代价是要滚 */
  const [actual, setActual] = useState(false);
  const [dev, setDev] = useState(true);
  const [clock, setClock] = useState('');

  const iframeRef = useRef<HTMLIFrameElement | null>(null);
  const boxRef = useRef<HTMLDivElement | null>(null);

  const device = DEVICES.find(d => d.id === deviceId) || DEVICES[0];
  const custom = customW > 0 || customH > 0;
  const w = custom ? (customW || device.w) : (landscape ? device.h : device.w);
  const h = custom ? (customH || device.h) : (landscape ? device.w : device.h);
  const sab = custom ? 0 : device.sab;
  const sat = custom ? 0 : device.sat;
  const statusH = custom ? 20 : device.statusH;
  const notch = custom ? 'none' : device.notch;
  const radius = custom ? 0 : device.radius;

  // 状态栏压在内容上（刘海/灵动岛）还是独立一条（SE/iPad）
  const overlap = sat > 0;

  // ---------- 安全区注入 ----------
  // iframe 里 env(safe-area-inset-*) 恒为 0，
  // 覆盖 --sat/--sab 就能模拟出真机的安全区效果。
  const injectSafeArea = useCallback(() => {
    const doc = iframeRef.current?.contentDocument;
    if (!doc?.head) return;
    let s = doc.getElementById('__sab') as HTMLStyleElement | null;
    if (!s) {
      s = doc.createElement('style');
      s.id = '__sab';
      doc.head.appendChild(s);
    }
    s.textContent = `:root{--sab:${sab}px;--sat:${sat}px}`;
  }, [sab, sat]);

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

  // 状态栏时钟
  useEffect(() => {
    const tick = () => {
      const d = new Date();
      setClock(`${d.getHours()}:${String(d.getMinutes()).padStart(2, '0')}`);
    };
    tick();
    const t = setInterval(tick, 15000);
    return () => clearInterval(t);
  }, []);

  // 缩放：整台设备必须**一屏装得下**，不能靠滚轮翻。
  // 宽高两个方向都要算，取更小的那个比例。
  useEffect(() => {
    const fit = () => {
      const box = boxRef.current;
      if (!box) return;
      const availW = box.clientWidth - 16;
      const availH = box.clientHeight - 16;
      setScale(actual ? 1 : Math.min(1, availW / w, availH / h));
    };
    fit();
    window.addEventListener('resize', fit);
    const t = setTimeout(fit, 120);
    return () => { window.removeEventListener('resize', fit); clearTimeout(t); };
  }, [w, h, actual]);

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
        <span className="text-xs font-semibold text-[#1C1C1C]">设备</span>

        <select
          value={custom ? 'custom' : deviceId}
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

        <button
          onClick={() => setActual(v => !v)}
          className={`px-2 py-1 rounded text-[11px] ${actual ? 'bg-[#ED6A3B] text-white' : 'bg-[#F3F1ED] text-[#5C5C5C] hover:bg-[#E8E4DF]'}`}
          title="1:1 真实像素尺寸（会需要滚动）"
        >
          {actual ? '1:1 真实尺寸' : '适应窗口'}
        </button>

        <span className="text-[11px] text-[#A0A0A0]">
          视口 {w}×{h} · 顶部 {sat}px · 底部 {sab}px · 显示 {Math.round(scale * 100)}%
        </span>
        <span className="text-[11px] text-[#A0A0A0] ml-auto">
          画面里按 Alt+I 开标注，点完直接粘给我
        </span>
      </div>

      {/* 画布 */}
      <div ref={boxRef} className={`flex-1 p-2 ${actual ? 'overflow-auto' : 'overflow-hidden'}`}>
        <div
          style={{
            width: w * scale,
            height: h * scale,
            overflow: 'hidden',
            borderRadius: radius * scale,
            boxShadow: '0 6px 32px rgba(0,0,0,0.22)',
            background: '#fff',
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
            {/* 状态栏压在内容上时，网页占满全屏；否则网页从状态栏下面开始 */}
            <iframe
              ref={iframeRef}
              src="/"
              title="设备画布"
              onLoad={() => { injectSafeArea(); setTimeout(injectSafeArea, 400); }}
              style={{
                position: 'absolute',
                left: 0,
                top: overlap ? 0 : statusH,
                width: '100%',
                height: overlap ? '100%' : h - statusH,
                border: 0,
                display: 'block',
              }}
            />

            {/* 设备装饰层（近似画法，只为判断元素会不会压到刘海/手势条/状态栏） */}
            <div className="absolute inset-0 pointer-events-none">
              {/* 状态栏 */}
              <div
                className="absolute left-0 right-0 top-0 flex items-center justify-between px-6"
                style={{
                  height: statusH,
                  background: overlap ? 'transparent' : '#F7F5F2',
                  color: '#000',
                }}
              >
                <span className="font-semibold tabular-nums" style={{ fontSize: statusH >= 55 ? 17 : 15 }}>
                  {clock}
                </span>
                <div className="flex items-center gap-1.5">
                  <svg width="17" height="12" viewBox="0 0 17 12" fill="currentColor" aria-hidden>
                    <rect x="0" y="7.5" width="3" height="4.5" rx="1" />
                    <rect x="4.7" y="5" width="3" height="7" rx="1" />
                    <rect x="9.4" y="2.5" width="3" height="9.5" rx="1" />
                    <rect x="14.1" y="0" width="3" height="12" rx="1" />
                  </svg>
                  <svg width="16" height="12" viewBox="0 0 16 12" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" aria-hidden>
                    <path d="M1 4.3a10.6 10.6 0 0 1 14 0" />
                    <path d="M3.7 7.2a6.8 6.8 0 0 1 8.6 0" />
                    <path d="M6.3 10a3 3 0 0 1 3.4 0" />
                    <circle cx="8" cy="11.4" r="0.9" fill="currentColor" stroke="none" />
                  </svg>
                  <svg width="26" height="13" viewBox="0 0 26 13" aria-hidden>
                    <rect x="0.6" y="0.6" width="21" height="11.8" rx="3.4" fill="none" stroke="currentColor" strokeOpacity="0.4" strokeWidth="1.1" />
                    <rect x="2.2" y="2.2" width="15" height="8.6" rx="2" fill="currentColor" />
                    <path d="M23.2 4.6v3.8a2.6 2.6 0 0 0 0-3.8z" fill="currentColor" fillOpacity="0.4" />
                  </svg>
                </div>
              </div>

              {notch === 'notch' && (
                <div className="absolute top-0 left-1/2 -translate-x-1/2 bg-black z-30"
                  style={{ width: 162, height: 32, borderRadius: '0 0 18px 18px' }} />
              )}
              {notch === 'island' && (
                <div className="absolute top-2 left-1/2 -translate-x-1/2 bg-black z-30"
                  style={{ width: 126, height: 37, borderRadius: 20 }} />
              )}
              {sab > 0 && (
                <div className="absolute bottom-1.5 left-1/2 -translate-x-1/2 bg-black/35 z-30"
                  style={{ width: 140, height: 5, borderRadius: 3 }} />
              )}
              {radius > 0 && (
                <div className="absolute inset-0 z-30" style={{
                  borderRadius: radius,
                  boxShadow: 'inset 0 0 0 1px rgba(0,0,0,0.08)',
                }} />
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
