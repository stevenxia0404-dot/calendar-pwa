'use client';

/**
 * 开发期设备画布 —— 只在 next dev 里有意义
 *
 * 为什么要它：WorkBuddy 的预览面板是窄的（<768px），只能看到移动版。
 * 但「这个按钮在 iPhone 14 Pro Max 上会不会太挤」「iPad 上会不会太空」
 * 这些问题，只有在真机尺寸下才看得出来。
 *
 * 做法：把应用装进一个指定尺寸的 iframe。
 * iframe 内部视口 = 指定尺寸 → Tailwind 的 md: 断点真按那个宽度算，
 * 不是把移动版硬掰一下（那样 CSS 媒体查询和 isNarrow 逻辑会打架）。
 *
 * 尺寸数据用真机的 CSS 像素视口（竖屏），
 * 安全区按机型给值 —— iframe 里 env(safe-area-inset-*) 恒为 0，
 * 所以靠注入 --sat / --sab 变量来模拟（app 那边已改成用 var()）。
 *
 * 状态栏分两种情况（这决定布局对不对）：
 *   有刘海/灵动岛 → 状态栏**盖在内容上**，app 要自己留出 --sat
 *   无刘海（SE）/ iPad → 状态栏是独立一条，网页从它下面开始（--sat = 0）
 *
 * ─────────────────────────────────────────────────────────────
 * 这个文件是**自包含**的（只 import react），可以直接拷到任何项目：
 *   cp <此文件> <项目>/src/app/dev-frame/page.tsx
 * 不依赖项目里的任何组件、样式变量或 API。
 * ─────────────────────────────────────────────────────────────
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';

type Mode = 'mobile' | 'desktop';
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

/** 标注器记录的一条 —— 与 app 里 Inspector.tsx 的 Mark 结构对齐 */
interface DevMark {
  n: number;
  component: string;
  componentChain: string[];
  selector: string;
  tag: string;
  text: string;
  ariaLabel: string;
  rect: { x: number; y: number; w: number; h: number };
  viewport: { w: number; h: number; isMobile: boolean };
  html: string;
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

/**
 * 桌面端的宽度预设。w=0 表示「铺满窗口」。
 *
 * 默认是「铺满」—— iframe 的宽度 = 画布宽度，1:1 不缩放。
 * 这样不管窗口多宽多窄，看到的都是真实的桌面布局，
 * 而不是被压扁的一条。固定宽度是给「我想看看 1024px 断点长什么样」用的。
 */
const DESKTOP_PRESETS = [
  { id: 'dfill', label: '铺满', desc: '跟随窗口', w: 0 },
  { id: 'd1280', label: '1280', desc: '笔记本', w: 1280 },
  { id: 'd1440', label: '1440', desc: '主流', w: 1440 },
  { id: 'd1920', label: '1920', desc: 'Full HD', w: 1920 },
];

/** 缩放范围 */
const ZOOM_MIN = 25;
const ZOOM_MAX = 300;
/** 「适应窗口」的最大倍率 —— 再大就没法看了，而且没必要 */
const FIT_MAX = 2;

/** 状态存哪 */
const STORAGE_KEY = 'devframe.v2';

export default function DevFrame() {
  const [dev, setDev] = useState(true);

  // ---------- 模式 ----------
  const [mode, setMode] = useState<Mode>('mobile');

  // ---------- 移动端 ----------
  const [deviceId, setDeviceId] = useState('ip14pro');
  const [landscape, setLandscape] = useState(false);
  const [customW, setCustomW] = useState(0);
  const [customH, setCustomH] = useState(0);

  // ---------- 桌面端 ----------
  const [desktopPreset, setDesktopPreset] = useState('dfill');

  // ---------- 缩放 ----------
  /** 'fit' = 适应窗口；'manual' = 手动百分比（可以超过 100%） */
  const [zoomMode, setZoomMode] = useState<'fit' | 'manual'>('fit');
  /** 手动的缩放**百分比**（25~300），不是倍率 —— 面板上显示的就是这个数 */
  const [zoom, setZoom] = useState(100);

  // ---------- 专注模式 ----------
  const [focus, setFocus] = useState(false);

  // ---------- 设置面板 ----------
  const [settingsOpen, setSettingsOpen] = useState(false);

  // ---------- 标注收集箱 ----------
  const [drawerOpen, setDrawerOpen] = useState(false);
  /** app 里的标注器现在开着没 */
  const [inspectorOn, setInspectorOn] = useState(false);
  /** 已标记的元素 —— 直接读 iframe 里的 window.__marks（同源，能读） */
  const [marks, setMarks] = useState<DevMark[]>([]);

  // ---------- 其他 ----------
  const [clock, setClock] = useState('');
  /** 画布容器尺寸（缩放要靠它算） */
  const [box, setBox] = useState({ w: 0, h: 0 });
  /** 状态恢复完了没有 —— 没恢复完不写 localStorage，否则默认值会把用户的设置冲掉 */
  const [ready, setReady] = useState(false);

  const iframeRef = useRef<HTMLIFrameElement | null>(null);
  const boxRef = useRef<HTMLDivElement | null>(null);

  const device = DEVICES.find(d => d.id === deviceId) || DEVICES[0];
  const custom = customW > 0 || customH > 0;

  // ---------- 视口尺寸：手机要画装饰，桌面不画 ----------
  const vp = useMemo(() => {
    if (mode === 'desktop') {
      // 桌面端高度跟随窗口，宽度按预设（铺满 = 容器宽度）
      const preset = DESKTOP_PRESETS.find(p => p.id === desktopPreset) || DESKTOP_PRESETS[0];
      return {
        w: preset.w || Math.max(320, box.w - 32),
        h: Math.max(320, box.h - 32),
        sat: 0, sab: 0, statusH: 0,
        notch: 'none' as Notch,
        radius: 0,
      };
    }
    const w = custom ? (customW || device.w) : (landscape ? device.h : device.w);
    const h = custom ? (customH || device.h) : (landscape ? device.w : device.h);
    return {
      w, h,
      sat: custom ? 0 : device.sat,
      sab: custom ? 0 : device.sab,
      statusH: custom ? 20 : device.statusH,
      notch: custom ? ('none' as Notch) : device.notch,
      radius: custom ? 0 : device.radius,
    };
  }, [mode, device, custom, customW, customH, landscape, desktopPreset, box.w, box.h]);

  // 状态栏压在内容上（刘海/灵动岛）还是独立一条（SE/iPad）
  const overlap = vp.sat > 0;

  // ---------- 缩放 ----------
  /**
   * 设备边框的厚度。
   *
   * 关键：边框必须画在**视口外面**。
   * 如果用 padding 往里挤，iframe 的布局视口就少了 2×BEZEL 像素 ——
   * 393px 的屏变成 381px，媒体断点可能因此翻车（Tailwind 的 md: 是 768px，
   * 但 sm:/xs: 那些断点就可能踩到）。
   * 所以：外框 = 视口 + 2×边框，屏幕严格等于视口尺寸。
   */
  const bezel = mode === 'mobile' ? 6 : 0;

  const fitScale = useMemo(() => {
    if (mode === 'desktop') {
      // 桌面端**永远 1:1，不缩放**。
      //
      // 为什么：桌面端锁的是「布局宽度」（1440 就是 1440），
      // 一缩放，缩出来的是一张看不清的糊图 —— 那条长条。
      // 窗口比预设窄的时候，正确做法是**横向滚动**去看右边，
      // 而不是把整个布局压扁。Chrome DevTools 的设备工具栏也是这么做的。
      return 1;
    }
    const availW = Math.max(80, box.w - 32);
    const availH = Math.max(80, box.h - 32);
    const raw = Math.min(availW / (vp.w + bezel * 2), availH / (vp.h + bezel * 2));
    // 手机端**允许超过 100%**：这是「看得更大」的唯一办法
    return Math.min(FIT_MAX, raw);
  }, [box.w, box.h, vp.w, vp.h, bezel, mode]);

  const scale = zoomMode === 'fit' ? fitScale : zoom / 100;

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
    s.textContent = `:root{--sab:${vp.sab}px;--sat:${vp.sat}px}`;
  }, [vp.sab, vp.sat]);

  /** 告诉 iframe「外面是设备画布」—— app 里的标注面板会据此让位 */
  const notifyHost = useCallback(() => {
    iframeRef.current?.contentWindow?.postMessage({ type: 'dev:host' }, '*');
  }, []);

  useEffect(() => { injectSafeArea(); }, [injectSafeArea]);

  // iframe 重新加载后要再注入一次
  useEffect(() => {
    const f = iframeRef.current;
    if (!f) return;
    const onLoad = () => {
      injectSafeArea();
      setTimeout(injectSafeArea, 400);
      notifyHost();
      setTimeout(notifyHost, 500);
    };
    f.addEventListener('load', onLoad);
    return () => f.removeEventListener('load', onLoad);
  }, [injectSafeArea, notifyHost]);

  // ---------- 状态栏时钟 ----------
  useEffect(() => {
    const tick = () => {
      const d = new Date();
      setClock(`${d.getHours()}:${String(d.getMinutes()).padStart(2, '0')}`);
    };
    tick();
    const t = setInterval(tick, 15000);
    return () => clearInterval(t);
  }, []);

  // ---------- 画布尺寸 ----------
  useEffect(() => {
    const el = boxRef.current;
    if (!el) return;
    const read = () => {
      setBox(prev => {
        const w = el.clientWidth, h = el.clientHeight;
        return prev.w === w && prev.h === h ? prev : { w, h };
      });
    };
    read();
    const ro = new ResizeObserver(read);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  // ---------- 状态恢复：URL 优先，其次 localStorage ----------
  useEffect(() => {
    const q = new URLSearchParams(window.location.search);

    // 先读 localStorage
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (raw) {
        const s = JSON.parse(raw) as Partial<{
          mode: Mode; deviceId: string; landscape: boolean;
          customW: number; customH: number; desktopPreset: string;
          zoomMode: 'fit' | 'manual'; zoom: number;
        }>;
        if (s.mode === 'mobile' || s.mode === 'desktop') setMode(s.mode);
        if (s.deviceId && DEVICES.some(d => d.id === s.deviceId)) setDeviceId(s.deviceId);
        if (typeof s.landscape === 'boolean') setLandscape(s.landscape);
        if (typeof s.customW === 'number') setCustomW(s.customW);
        if (typeof s.customH === 'number') setCustomH(s.customH);
        if (s.desktopPreset && DESKTOP_PRESETS.some(p => p.id === s.desktopPreset)) setDesktopPreset(s.desktopPreset);
        if (s.zoomMode === 'fit' || s.zoomMode === 'manual') setZoomMode(s.zoomMode);
        if (typeof s.zoom === 'number' && s.zoom > 0) setZoom(s.zoom);
      }
    } catch { /* 存坏了就当没有 */ }

    // URL 覆盖 localStorage（这样发出去的链接能复现状态）
    const qm = q.get('mode');
    if (qm === 'mobile' || qm === 'desktop') setMode(qm);
    const qd = q.get('d');
    if (qd && DEVICES.some(d => d.id === qd)) { setDeviceId(qd); setCustomW(0); setCustomH(0); }
    const qw = Number(q.get('w'));
    const qh = Number(q.get('h'));
    if (qw > 200) setCustomW(qw);
    if (qh > 200) setCustomH(qh);
    const qz = Number(q.get('z'));
    if (qz >= ZOOM_MIN && qz <= ZOOM_MAX) { setZoom(qz); setZoomMode('manual'); }
    if (q.get('fit') === '1') setZoomMode('fit');

    setDev(process.env.NODE_ENV === 'development');
    setReady(true);
  }, []);

  // ---------- 状态写回 ----------
  useEffect(() => {
    if (!ready) return;
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify({
        mode, deviceId, landscape, customW, customH,
        desktopPreset, zoomMode, zoom,
      }));
    } catch { /* 存不下就算了 */ }
  }, [ready, mode, deviceId, landscape, customW, customH, desktopPreset, zoomMode, zoom]);

  // ---------- 缩放操作 ----------
  // zoom 一律是**百分比**（25~300），scale 才是倍率。
  const setManualZoom = useCallback((pct: number) => {
    setZoomMode('manual');
    setZoom(Math.min(ZOOM_MAX, Math.max(ZOOM_MIN, Math.round(pct))));
  }, []);
  const zoomBy = useCallback((delta: number) => {
    // 从「适应」开始改的话，以当前实际显示的倍率为基准
    const base = zoomMode === 'fit' ? fitScale * 100 : zoom;
    setManualZoom(base + delta);
  }, [zoomMode, zoom, fitScale]);
  const fitNow = useCallback(() => { setZoomMode('fit'); }, []);

  // ---------- 标注：读 iframe 里的标注数据 ----------
  // app 里的 Inspector 把标记写在 window.__marks 上。
  // iframe 与画布同源，所以外层能直接读 —— 不用改 app。
  useEffect(() => {
    const read = () => {
      const w = iframeRef.current?.contentWindow as (Window & { __marks?: DevMark[] }) | null;
      const m = w?.__marks;
      setMarks(prev => {
        const next = m || [];
        return prev.length === next.length ? prev : next;
      });
    };
    read();
    const t = setInterval(read, 600);
    return () => clearInterval(t);
  }, []);

  // app 里的标注器开关状态 —— 画布得知道，才能把按钮画对
  useEffect(() => {
    const onMsg = (e: MessageEvent) => {
      const t = e.data?.type;
      if (t === 'dev:inspector-state') setInspectorOn(!!e.data.on);
      else if (t === 'dev:inspector-hello') {
        // 画布里那个 app 的标注器挂好了 —— 回一句，
        // 它的圆钮和面板就收起来，改由收集箱接管
        const src = e.source as Window | null;
        src?.postMessage({ type: 'dev:host' }, '*');
      }
    };
    window.addEventListener('message', onMsg);
    return () => window.removeEventListener('message', onMsg);
  }, []);

  const toggleInspector = useCallback(() => {
    iframeRef.current?.contentWindow?.postMessage({ type: 'dev:toggle-inspector' }, '*');
  }, []);
  const clearMarks = useCallback(() => {
    iframeRef.current?.contentWindow?.postMessage({ type: 'dev:clear-marks' }, '*');
    setMarks([]);
  }, []);

  // ---------- 快捷键 ----------
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement | null;
      // 在输入框里打字时不抢键盘
      if (t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT' || t.isContentEditable)) {
        if (e.key === 'Escape') (t as HTMLElement).blur();
        return;
      }
      if (e.metaKey || e.ctrlKey || e.altKey) return;

      switch (e.key) {
        case '1': setMode('mobile'); break;
        case '2': setMode('desktop'); break;
        case 'f': case 'F': setFocus(v => !v); break;
        case 'r': case 'R':
          if (mode === 'mobile') { setLandscape(v => !v); setCustomW(0); setCustomH(0); }
          break;
        case 'l': case 'L':
          // 标注器在 iframe 里面，外层的按键传不进去 —— 得转发
          iframeRef.current?.contentWindow?.postMessage({ type: 'dev:toggle-inspector' }, '*');
          break;
        case '+': case '=': zoomBy(10); break;
        case '-': case '_': zoomBy(-10); break;
        case '0': fitNow(); break;
        case 'Escape':
          if (settingsOpen) setSettingsOpen(false);
          else if (focus) setFocus(false);
          break;
        default: return;
      }
      e.preventDefault();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [mode, zoomBy, fitNow, focus, settingsOpen]);

  if (!dev) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#F7F5F2] text-[#8A8A8A] text-sm">
        这个页面只在开发环境里有意义
      </div>
    );
  }

  const scalePct = Math.round(scale * 100);

  return (
    // h-screen + overflow-hidden：画布页面自己**不滚动**，
    // 整台设备必须一屏装得下（放不下时是画布内部滚动，不是整页滚动）。
    <div className="h-screen overflow-hidden flex flex-col bg-[#33302C]">

      {/* ─────────── 工具条（36px）───────────
          专注模式下**整个不渲染** —— 不是 display:none。
          少一整个 DOM 节点，画布就能吃满高度。 */}
      {!focus && (
        <div className="shrink-0 h-9 bg-white border-b border-[#D9D4CF] px-3 flex items-center gap-2">
          {/* 模式切换 */}
          <div className="flex items-center p-[2px] rounded-md bg-[#F3F1ED] h-6">
            {([['mobile', '移动端'], ['desktop', '桌面端']] as const).map(([k, label]) => (
              <button
                key={k}
                onClick={() => setMode(k)}
                className={`h-[20px] px-2.5 rounded text-[11px] leading-none transition-colors ${
                  mode === k
                    ? 'bg-white text-[#1C1C1C] font-medium shadow-[0_1px_2px_rgba(0,0,0,0.08)]'
                    : 'text-[#8A8A8A] hover:text-[#5C5C5C]'
                }`}
              >
                {label}
              </button>
            ))}
          </div>

          {/* 设置 */}
          <button
            onClick={() => setSettingsOpen(true)}
            className="h-6 px-2.5 rounded text-[11px] leading-none text-[#5C5C5C] border border-[#E8E4DF] hover:border-[#C9C5BF] hover:bg-[#F7F5F2]"
          >
            设置
          </button>

          {/* 标注收集箱 */}
          <button
            onClick={() => setDrawerOpen(v => !v)}
            className={`h-6 px-2.5 rounded text-[11px] leading-none border transition-colors ${
              drawerOpen
                ? 'border-[#ED6A3B] bg-[#ED6A3B]/8 text-[#1C1C1C] font-medium'
                : 'text-[#5C5C5C] border-[#E8E4DF] hover:border-[#C9C5BF] hover:bg-[#F7F5F2]'
            }`}
            title="标注收集箱"
          >
            标注
            {marks.length > 0 && (
              <span className="ml-1 inline-block min-w-[14px] px-1 rounded-full bg-[#ED6A3B] text-white text-[9px] leading-[14px] align-middle">
                {marks.length}
              </span>
            )}
          </button>

          {/* 读数 + 专注 */}
          <div className="ml-auto flex items-center gap-2">
            <span className="text-[11px] text-[#8A8A8A] font-mono tabular-nums">
              {vp.w}×{vp.h} · {scalePct}%
            </span>
            <button
              onClick={() => setFocus(true)}
              className="h-6 px-2.5 rounded text-[11px] leading-none text-[#5C5C5C] border border-[#E8E4DF] hover:border-[#C9C5BF] hover:bg-[#F7F5F2]"
            >
              专注
            </button>
          </div>
        </div>
      )}

      {/* ─────────── 画布 ───────────
          overflow-auto：设备放大到超出画布时，这里出滚动条（可以平移看细节）。
          min-h-0：flex 子项默认 min-height:auto，内容多高它就多高，
          flex-1 的高度上限就失效了。不加这个，画布永远撑破容器。 */}
      <div ref={boxRef} className="flex-1 min-h-0 overflow-auto">
        {/* min-h-full/min-w-full + 子元素 margin:auto ——
            flex 居中遇到溢出时，左上角会滚不到。用 margin:auto 才不会出这个毛病。 */}
        <div className="min-h-full min-w-full flex p-4">
          <div
            style={{
              margin: 'auto',
              width: (vp.w + bezel * 2) * scale,
              height: (vp.h + bezel * 2) * scale,
              flex: 'none',
            }}
          >
            {/* 设备外壳（真机边框感）—— 桌面端没有。
                外框比视口大 2×bezel，屏幕严格等于视口 —— 边框不占布局宽度。 */}
            <div
              style={{
                width: vp.w + bezel * 2, height: vp.h + bezel * 2,
                transform: `scale(${scale})`,
                transformOrigin: 'top left',
                position: 'relative',
                borderRadius: mode === 'mobile' ? vp.radius + bezel : 0,
                background: mode === 'mobile' ? '#0E0D0C' : 'transparent',
                padding: bezel,
                boxShadow: mode === 'mobile' ? '0 10px 44px rgba(0,0,0,0.45)' : 'none',
                boxSizing: 'border-box',
              }}
            >
              {/* 屏幕 —— 严格 = 视口尺寸 */}
              <div
                style={{
                  width: vp.w, height: vp.h,
                  borderRadius: mode === 'mobile' ? vp.radius : 0,
                  overflow: 'hidden',
                  position: 'relative',
                  background: '#fff',
                }}
              >
                {/* 状态栏压在内容上时，网页占满全屏；否则网页从状态栏下面开始 */}
                <iframe
                  ref={iframeRef}
                  src="/"
                  title="设备画布"
                  onLoad={() => { injectSafeArea(); setTimeout(injectSafeArea, 400); notifyHost(); setTimeout(notifyHost, 500); }}
                  style={{
                    position: 'absolute',
                    left: 0,
                    top: overlap ? 0 : vp.statusH,
                    width: '100%',
                    height: overlap ? '100%' : `calc(100% - ${vp.statusH}px)`,
                    border: 0,
                    display: 'block',
                  }}
                />

                {/* 设备装饰层（近似画法，只为判断元素会不会压到刘海/手势条/状态栏）*/}
                {mode === 'mobile' && (
                  <div className="absolute inset-0 pointer-events-none">
                    {/* 状态栏 */}
                    <div
                      className="absolute left-0 right-0 top-0 flex items-center justify-between px-6"
                      style={{
                        height: vp.statusH,
                        background: overlap ? 'transparent' : '#F7F5F2',
                        color: '#000',
                      }}
                    >
                      <span className="font-semibold tabular-nums" style={{ fontSize: vp.statusH >= 55 ? 17 : 15 }}>
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

                    {vp.notch === 'notch' && (
                      <div className="absolute top-0 left-1/2 -translate-x-1/2 bg-black z-30"
                        style={{ width: 162, height: 32, borderRadius: '0 0 18px 18px' }} />
                    )}
                    {vp.notch === 'island' && (
                      <div className="absolute top-2 left-1/2 -translate-x-1/2 bg-black z-30"
                        style={{ width: 126, height: 37, borderRadius: 20 }} />
                    )}
                    {vp.sab > 0 && (
                      <div className="absolute bottom-1.5 left-1/2 -translate-x-1/2 bg-black/35 z-30"
                        style={{ width: 140, height: 5, borderRadius: 3 }} />
                    )}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* ─────────── 专注模式的提示胶囊 ─────────── */}
      {focus && (
        <div className="fixed bottom-3 left-1/2 -translate-x-1/2 flex items-center gap-2 px-3 h-8 rounded-full bg-[#1C1C1C]/85 text-[#D3D1C7] text-[11px] select-none z-50">
          <span className="font-mono tabular-nums">{vp.w}×{vp.h} · {scalePct}%</span>
          <span className="w-px h-3 bg-[#5F5E5A]" />
          <span>Esc 退出 · Alt+I 标注 · F 专注</span>
        </div>
      )}

      {/* ─────────── 标注收集箱 ───────────
          浮在画布上面（不是挤占画布宽度）——
          否则一打开收集箱，手机就被挤小了，看标注反而费劲。 */}
      {drawerOpen && (
        <MarkDrawer
          marks={marks}
          inspectorOn={inspectorOn}
          onToggleInspector={toggleInspector}
          onClear={clearMarks}
          onClose={() => setDrawerOpen(false)}
        />
      )}

      {/* ─────────── 设置面板 ─────────── */}
      {settingsOpen && (
        <SettingsPanel
          mode={mode}
          deviceId={deviceId}
          custom={custom}
          customW={customW}
          customH={customH}
          landscape={landscape}
          desktopPreset={desktopPreset}
          zoomMode={zoomMode}
          zoom={zoom}
          fitScale={fitScale}
          onClose={() => setSettingsOpen(false)}
          onMode={setMode}
          onDevice={(id) => { setDeviceId(id); setCustomW(0); setCustomH(0); }}
          onCustom={(w, h) => { setCustomW(w); setCustomH(h); }}
          onLandscape={(v) => { setLandscape(v); setCustomW(0); setCustomH(0); }}
          onDesktopPreset={setDesktopPreset}
          onZoomMode={(m) => { if (m === 'fit') fitNow(); else setManualZoom(zoom); }}
          onZoom={setManualZoom}
        />
      )}
    </div>
  );
}

/* ==================================================================
   标注收集箱
   ------------------------------------------------------------------
   为什么要有它：原来标一个元素就得复制一次，改三处要来回翻聊天记录三趟。
   现在标完攒在这儿，一次「复制全部」给我。

   数据是从 iframe 里的 window.__marks 直接读的（同源）。
   ================================================================== */

function MarkDrawer({
  marks, inspectorOn, onToggleInspector, onClear, onClose,
}: {
  marks: DevMark[];
  inspectorOn: boolean;
  onToggleInspector: () => void;
  onClear: () => void;
  onClose: () => void;
}) {
  const [copied, setCopied] = useState(false);
  /** 刚复制的是第几条 —— 在条目上给个 ✓ */
  const [copiedOne, setCopiedOne] = useState<number | null>(null);
  /** 哪一条展开了 HTML */
  const [openHtml, setOpenHtml] = useState<number | null>(null);

  const copyAll = async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(marks, null, 2));
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    } catch { /* 剪贴板不可用就手动选 */ }
  };
  const copyOne = async (m: DevMark) => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(m, null, 2));
      setCopiedOne(m.n);
      setTimeout(() => setCopiedOne(c => (c === m.n ? null : c)), 1500);
    } catch { /* 剪贴板不可用就手动选 */ }
  };

  return (
    <div className="fixed top-0 right-0 bottom-0 w-[320px] bg-white border-l border-[#D9D4CF] shadow-[-8px_0_32px_rgba(0,0,0,0.18)] z-40 flex flex-col">
      {/* 头部 */}
      <div className="shrink-0 px-3 h-11 flex items-center justify-between border-b border-[#EDE9E4]">
        <div className="flex items-center gap-2">
          <h2 className="text-[13px] font-semibold text-[#1C1C1C]">标注收集箱</h2>
          <span className="text-[11px] text-[#8A8A8A] font-mono">{marks.length}</span>
        </div>
        <button
          onClick={onClose}
          className="w-6 h-6 rounded text-[#8A8A8A] hover:bg-[#F3F1ED] text-[15px] leading-none"
          aria-label="关闭收集箱"
        >
          ×
        </button>
      </div>

      {/* 标注模式开关 */}
      <div className="shrink-0 px-3 py-2.5 border-b border-[#EDE9E4]">
        <button
          onClick={onToggleInspector}
          className={`w-full h-8 rounded-lg text-[12px] border transition-colors ${
            inspectorOn
              ? 'bg-[#ED6A3B] border-[#ED6A3B] text-white'
              : 'border-[#E8E4DF] text-[#5C5C5C] hover:bg-[#F7F5F2]'
          }`}
        >
          {inspectorOn ? '标注模式：开 · 点元素标记' : '开启标注模式（Alt+I / L）'}
        </button>
        <p className="mt-1.5 text-[11px] text-[#8A8A8A] leading-relaxed">
          {inspectorOn
            ? '现在点画面里的元素就能标记，标完在这里一次复制。'
            : '开了之后点画面里的元素，会记下组件名、选择器、坐标、样式。'}
        </p>
      </div>

      {/* 列表 */}
      <div className="flex-1 min-h-0 overflow-y-auto">
        {marks.length === 0 ? (
          <div className="px-4 py-8 text-center">
            <p className="text-[12px] text-[#8A8A8A]">还没标任何东西</p>
            <p className="mt-1 text-[11px] text-[#B4B2A9]">开启标注模式后点画面里的元素</p>
          </div>
        ) : (
          <div className="divide-y divide-[#F3F1ED]">
            {marks.map(m => {
              const htmlOpen = openHtml === m.n;
              const justCopied = copiedOne === m.n;
              return (
                <div key={m.n} className="px-3 py-2">
                  {/* 点条目 = 复制这一条 */}
                  <button
                    onClick={() => copyOne(m)}
                    className="w-full text-left hover:opacity-75 transition-opacity"
                    title="点这条复制这一条的完整信息"
                  >
                    <div className="flex items-center gap-1.5">
                      <span className="text-[10px] font-mono text-[#ED6A3B] bg-[#ED6A3B]/10 rounded px-1">{m.n}</span>
                      <span className="text-[12px] font-medium text-[#1C1C1C] truncate">
                        {m.component || m.tag}
                      </span>
                      {m.viewport?.isMobile && (
                        <span className="text-[9px] text-[#8A8A8A] border border-[#E8E4DF] rounded px-1 shrink-0">手机</span>
                      )}
                      {justCopied && (
                        <span className="text-[10px] text-[#4E7D6C] font-medium shrink-0">✓ 已复制</span>
                      )}
                    </div>
                    {m.text && (
                      <div className="mt-0.5 text-[11px] text-[#5C5C5C] truncate">{m.text}</div>
                    )}
                    <div className="mt-0.5 text-[10px] text-[#A8A49E] font-mono truncate">{m.selector}</div>
                    <div className="mt-0.5 text-[10px] text-[#A8A49E] font-mono">
                      {Math.round(m.rect?.w || 0)}×{Math.round(m.rect?.h || 0)}
                      {' @ '}{Math.round(m.rect?.x || 0)},{Math.round(m.rect?.y || 0)}
                    </div>
                  </button>

                  {/* 看源码 —— 不用复制出去就能瞄一眼 */}
                  <div className="mt-1">
                    <button
                      onClick={() => setOpenHtml(htmlOpen ? null : m.n)}
                      className="text-[10px] text-[#8A8A8A] hover:text-[#ED6A3B] transition-colors"
                    >
                      {htmlOpen ? '收起 HTML ▴' : '看 HTML ▾'}
                    </button>
                    {htmlOpen && (
                      <pre className="mt-1 p-2 rounded bg-[#F7F5F2] border border-[#EDE9E4] text-[10px] leading-[1.5] font-mono text-[#5C5C5C] whitespace-pre-wrap break-all max-h-[180px] overflow-y-auto">
                        {m.html}
                      </pre>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* 底部操作 */}
      <div className="shrink-0 px-3 py-2.5 border-t border-[#EDE9E4] flex gap-2">
        <button
          onClick={copyAll}
          disabled={marks.length === 0}
          className={`flex-1 h-8 rounded-lg text-[12px] transition-colors ${
            marks.length === 0
              ? 'bg-[#F3F1ED] text-[#C0BDB8] cursor-not-allowed'
              : copied
                ? 'bg-[#4E7D6C] text-white'
                : 'bg-[#ED6A3B] text-white hover:bg-[#D45D2E]'
          }`}
        >
          {copied ? '已复制 ✓' : `复制全部（${marks.length}）`}
        </button>
        <button
          onClick={onClear}
          disabled={marks.length === 0}
          className="h-8 px-3 rounded-lg text-[12px] border border-[#E8E4DF] text-[#5C5C5C] hover:bg-[#F7F5F2] disabled:opacity-40"
        >
          清空
        </button>
      </div>
    </div>
  );
}

/* ==================================================================
   设置面板
   ================================================================== */

function SettingsPanel({
  mode, deviceId, custom, customW, customH, landscape, desktopPreset,
  zoomMode, zoom, fitScale,
  onClose, onMode, onDevice, onCustom, onLandscape, onDesktopPreset, onZoomMode, onZoom,
}: {
  mode: Mode;
  deviceId: string;
  custom: boolean;
  customW: number;
  customH: number;
  landscape: boolean;
  desktopPreset: string;
  zoomMode: 'fit' | 'manual';
  zoom: number;
  fitScale: number;
  onClose: () => void;
  onMode: (m: Mode) => void;
  onDevice: (id: string) => void;
  onCustom: (w: number, h: number) => void;
  onLandscape: (v: boolean) => void;
  onDesktopPreset: (id: string) => void;
  onZoomMode: (m: 'fit' | 'manual') => void;
  onZoom: (v: number) => void;
}) {
  const device = DEVICES.find(d => d.id === deviceId) || DEVICES[0];
  const effW = custom ? (customW || device.w) : (landscape ? device.h : device.w);
  const effH = custom ? (customH || device.h) : (landscape ? device.w : device.h);

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ background: 'rgba(0,0,0,0.45)' }}
      onClick={onClose}
    >
      <div
        className="w-full max-w-[380px] rounded-2xl bg-white shadow-2xl overflow-hidden"
        onClick={e => e.stopPropagation()}
      >
        {/* 头部 */}
        <div className="flex items-center justify-between px-4 h-11 border-b border-[#EDE9E4]">
          <h2 className="text-[13px] font-semibold text-[#1C1C1C]">画布设置</h2>
          <button
            onClick={onClose}
            className="w-6 h-6 rounded text-[#8A8A8A] hover:bg-[#F3F1ED] text-[15px] leading-none"
            aria-label="关闭"
          >
            ×
          </button>
        </div>

        <div className="p-4 flex flex-col gap-4 max-h-[70vh] overflow-y-auto">

          {/* 模式 */}
          <div>
            <Label>呈现方式</Label>
            <div className="flex items-center p-[2px] rounded-md bg-[#F3F1ED] h-8">
              {([['mobile', '移动端'], ['desktop', '桌面端']] as const).map(([k, label]) => (
                <button
                  key={k}
                  onClick={() => onMode(k)}
                  className={`flex-1 h-[26px] rounded text-[12px] leading-none transition-colors ${
                    mode === k
                      ? 'bg-white text-[#1C1C1C] font-medium shadow-[0_1px_2px_rgba(0,0,0,0.08)]'
                      : 'text-[#8A8A8A] hover:text-[#5C5C5C]'
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>
          </div>

          {/* 移动端：设备型号 */}
          {mode === 'mobile' && (
            <div>
              <Label>设备型号</Label>
              <div className="rounded-lg border border-[#E8E4DF] overflow-hidden max-h-[190px] overflow-y-auto">
                {(['iPhone', 'iPad'] as const).map(g => (
                  <div key={g}>
                    <div className="px-2.5 py-1 bg-[#F7F5F2] text-[10px] text-[#8A8A8A]">{g}</div>
                    {DEVICES.filter(d => d.group === g).map(d => (
                      <button
                        key={d.id}
                        onClick={() => onDevice(d.id)}
                        className={`w-full text-left px-2.5 py-1.5 text-[12px] flex items-center justify-between border-t border-[#F3F1ED] transition-colors ${
                          !custom && deviceId === d.id
                            ? 'bg-[#ED6A3B]/8 text-[#1C1C1C] font-medium'
                            : 'text-[#5C5C5C] hover:bg-[#F7F5F2]'
                        }`}
                      >
                        <span>{d.label}</span>
                        <span className="text-[10px] text-[#8A8A8A] font-mono">{d.w}×{d.h}</span>
                      </button>
                    ))}
                  </div>
                ))}
              </div>
              {custom && (
                <p className="mt-1.5 text-[11px] text-[#ED6A3B]">
                  当前用的是自定义尺寸 —— 选上面任一机型即可切回
                </p>
              )}
            </div>
          )}

          {/* 桌面端：宽度预设 */}
          {mode === 'desktop' && (
            <div>
              <Label>视口宽度</Label>
              <div className="grid grid-cols-4 gap-1.5">
                {DESKTOP_PRESETS.map(p => (
                  <button
                    key={p.id}
                    onClick={() => onDesktopPreset(p.id)}
                    className={`py-1.5 rounded-lg border text-[12px] leading-tight transition-colors ${
                      desktopPreset === p.id
                        ? 'border-[#ED6A3B] bg-[#ED6A3B]/8 text-[#1C1C1C] font-medium'
                        : 'border-[#E8E4DF] text-[#5C5C5C] hover:bg-[#F7F5F2]'
                    }`}
                  >
                    {p.label}
                    <span className="block text-[9px] text-[#8A8A8A] font-normal">{p.desc}</span>
                  </button>
                ))}
              </div>
              <p className="mt-1.5 text-[11px] text-[#8A8A8A]">
                高度跟随窗口。桌面端没有状态栏、灵动岛、手势条 —— 就是普通浏览器窗口。
              </p>
            </div>
          )}

          {/* 视口尺寸 */}
          {mode === 'mobile' && (
            <div>
              <Label>视口尺寸</Label>
              <div className="flex items-center gap-2">
                <NumBox value={effW} onChange={v => onCustom(v, effH)} label="宽" />
                <NumBox value={effH} onChange={v => onCustom(effW, v)} label="高" />
                <button
                  onClick={() => onLandscape(!landscape)}
                  className="h-8 px-3 rounded-lg border border-[#E8E4DF] text-[12px] text-[#5C5C5C] hover:bg-[#F7F5F2] shrink-0"
                >
                  {landscape ? '竖屏' : '横屏'}
                </button>
              </div>
            </div>
          )}

          {/* 显示比例 */}
          <div>
            <div className="flex items-baseline justify-between mb-1.5">
              <Label>显示比例</Label>
              <span className="text-[12px] font-mono tabular-nums text-[#1C1C1C]">
                {zoomMode === 'fit' ? Math.round(fitScale * 100) : zoom}%
              </span>
            </div>
            <input
              type="range"
              min={ZOOM_MIN}
              max={ZOOM_MAX}
              step={1}
              value={zoomMode === 'fit' ? Math.round(fitScale * 100) : zoom}
              onChange={e => onZoom(Number(e.target.value))}
              className="w-full accent-[#ED6A3B]"
              aria-label="显示比例"
            />
            <div className="flex gap-1.5 mt-2">
              <Chip active={zoomMode === 'fit'} onClick={() => onZoomMode('fit')}>
                适应窗口 {Math.round(fitScale * 100)}%
              </Chip>
              <Chip active={zoomMode === 'manual' && zoom === 100} onClick={() => onZoom(100)}>100%</Chip>
              <Chip active={zoomMode === 'manual' && zoom === 150} onClick={() => onZoom(150)}>150%</Chip>
              <Chip active={zoomMode === 'manual' && zoom === 200} onClick={() => onZoom(200)}>200%</Chip>
            </div>
            <p className="mt-2 text-[11px] text-[#8A8A8A] leading-relaxed">
              超过 100% 后画面会超出画布，用滚动条或拖动画布空白处平移查看细节。
            </p>
          </div>

          {/* 快捷键 */}
          <div>
            <Label>快捷键</Label>
            <div className="rounded-lg border border-[#E8E4DF] divide-y divide-[#F3F1ED]">
              {[
                ['1 / 2', '移动端 / 桌面端'],
                ['F', '专注模式（Esc 退出）'],
                ['R', '横竖屏切换'],
                ['L', '标注器开关'],
                ['+ / -', '缩放 ±10%'],
                ['0', '适应窗口'],
              ].map(([k, d]) => (
                <div key={k} className="flex items-center justify-between px-2.5 py-1.5">
                  <kbd className="text-[11px] font-mono text-[#1C1C1C] bg-[#F3F1ED] rounded px-1.5 py-0.5">{k}</kbd>
                  <span className="text-[11px] text-[#8A8A8A]">{d}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function Label({ children }: { children: React.ReactNode }) {
  return <label className="block text-[11px] text-[#8A8A8A] mb-1.5">{children}</label>;
}

function NumBox({
  value, onChange, label,
}: { value: number; onChange: (v: number) => void; label: string }) {
  return (
    <div className="flex-1 min-w-0">
      <div className="text-[10px] text-[#A8A49E] mb-0.5">{label}</div>
      <input
        type="number"
        value={value}
        onChange={e => {
          const v = Number(e.target.value);
          if (!Number.isNaN(v) && v > 200 && v < 3000) onChange(Math.round(v));
        }}
        className="w-full h-8 px-2 rounded-lg border border-[#E8E4DF] text-[12px] font-mono text-[#1C1C1C] outline-none focus:border-[#ED6A3B]"
      />
    </div>
  );
}

function Chip({
  active, onClick, children,
}: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      onClick={onClick}
      className={`px-2 h-7 rounded-lg text-[11px] border transition-colors ${
        active
          ? 'border-[#ED6A3B] bg-[#ED6A3B]/8 text-[#1C1C1C] font-medium'
          : 'border-[#E8E4DF] text-[#8A8A8A] hover:bg-[#F7F5F2]'
      }`}
    >
      {children}
    </button>
  );
}
