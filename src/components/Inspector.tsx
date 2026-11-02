'use client';

// 开发期标注器 —— 只在 next dev 里渲染，生产构建整个组件不出现
//
// 解决的问题：改 UI 的时候，「你指哪我改哪」不能靠文字描述。
// 说「那个按钮太小了」，我得靠猜；截图圈一下，我只知道大概位置。
//
// 这个组件让 Steven 直接点页面上的元素，自动记下：
//   是什么（React 组件名）、在哪（视口坐标 + 尺寸）、长什么样（计算样式）、
//   是谁（CSS 选择器路径 + outerHTML）
//
// 数据挂在 window.__marks 上，我用 CDP 直接读 —— 他标完说一声，
// 我这边就拿到了完整的结构化描述，不用他打字。

import { useCallback, useEffect, useRef, useState } from 'react';

interface MarkStyle {
  color: string;
  background: string;
  fontSize: string;
  fontWeight: string;
  lineHeight: string;
  borderRadius: string;
  padding: string;
  margin: string;
  border: string;
  boxShadow: string;
  display: string;
  flexDirection: string;
  gap: string;
  opacity: string;
}

interface Mark {
  n: number;
  component: string;
  componentChain: string[];
  selector: string;
  tag: string;
  cls: string;
  text: string;
  ariaLabel: string;
  rect: { x: number; y: number; w: number; h: number };
  viewport: { w: number; h: number; isMobile: boolean };
  style: MarkStyle;
  html: string;
}

declare global {
  interface Window {
    __marks?: Mark[];
  }
}

const STYLE_KEYS: (keyof MarkStyle)[] = [
  'color', 'background', 'fontSize', 'fontWeight', 'lineHeight', 'borderRadius',
  'padding', 'margin', 'border', 'boxShadow', 'display', 'flexDirection', 'gap', 'opacity',
];

/** 生成一个尽量稳的 CSS 选择器：优先 id / aria-label / data-*，否则走 nth-of-type 路径 */
function cssPath(el: Element): string {
  const parts: string[] = [];
  let cur: Element | null = el;
  let depth = 0;

  while (cur && cur.nodeType === 1 && depth++ < 8) {
    // 有稳定标识就直接用，不用往下走
    const id = cur.getAttribute('id');
    if (id && /^[A-Za-z][\w-]*$/.test(id)) {
      parts.unshift(`#${id}`);
      break;
    }
    const aria = cur.getAttribute('aria-label');
    if (aria) {
      parts.unshift(`${cur.tagName.toLowerCase()}[aria-label="${aria}"]`);
      break;
    }
    const testid = cur.getAttribute('data-testid');
    if (testid) {
      parts.unshift(`${cur.tagName.toLowerCase()}[data-testid="${testid}"]`);
      break;
    }

    let seg = cur.tagName.toLowerCase();
    const parent: Element | null = cur.parentElement;
    if (parent) {
      const sameTag = Array.from(parent.children).filter(c => c.tagName === cur!.tagName);
      if (sameTag.length > 1) seg += `:nth-of-type(${sameTag.indexOf(cur) + 1})`;
    }
    parts.unshift(seg);
    cur = parent;
  }

  return parts.join(' > ');
}

/** 往上找最近的函数组件 —— 知道是哪个组件里的东西，我就能直接定位到文件 */
function reactInfo(el: Element): { component: string; chain: string[] } {
  const chain: string[] = [];
  try {
    const key = Object.keys(el).find(k => k.startsWith('__reactFiber$'));
    if (!key) return { component: '', chain };
    let fiber = (el as unknown as Record<string, unknown>)[key] as {
      type?: unknown; return?: unknown; tag?: number;
    } | null;

    let depth = 0;
    while (fiber && depth++ < 25) {
      const t = fiber.type as { displayName?: string; name?: string } | string | undefined;
      const isHost = typeof t === 'string';
      const name = isHost
        ? (t as string)
        : ((t as { displayName?: string; name?: string })?.displayName || (t as { name?: string })?.name || '');
      if (name && !chain.includes(name)) chain.push(name);
      fiber = fiber.return as typeof fiber;
    }
  } catch {
    // 拿不到就算了，不影响其它信息
  }

  // 第一个非 host 的就是拥有它的组件
  const component = chain.find(c => c !== 'div' && c !== 'span' && c !== 'button' && c !== 'a'
    && c !== 'p' && c !== 'input' && c !== 'textarea' && c !== 'ul' && c !== 'li' && c !== 'h1'
    && c !== 'h2' && c !== 'h3' && c !== 'label' && c !== 'section' && c !== 'header'
    && c !== 'footer' && c !== 'main' && c !== 'nav' && c !== 'img' && c !== 'svg') || '';

  return { component, chain };
}

/** 当前生效的视口宽度 —— 桌面画布里 iframe 的宽度就是布局依据 */
function effectiveWidth(): number {
  return window.innerWidth;
}

function readStyle(el: Element): MarkStyle {
  const cs = getComputedStyle(el);
  const out = {} as MarkStyle;
  for (const k of STYLE_KEYS) {
    // CSSStyleDeclaration 的索引签名不在类型里，用 Record 转换而不是 any
    const v = (cs as unknown as Record<string, string>)[k];
    if (v) out[k] = String(v);
  }
  return out;
}

export default function Inspector() {
  const [on, setOn] = useState(false);
  const [marks, setMarks] = useState<Mark[]>([]);
  const [hover, setHover] = useState<{ x: number; y: number; w: number; h: number; label: string } | null>(null);
  const [panelOpen, setPanelOpen] = useState(true);
  /** 刚自动复制了几条 —— 面板上给个「已复制」反馈 */
  const [copied, setCopied] = useState(0);

  const hoverRef = useRef<{ x: number; y: number; w: number; h: number; label: string } | null>(null);
  const badgeLayerRef = useRef<HTMLDivElement | null>(null);
  const markedElsRef = useRef<Element[]>([]);

  // ---------- 记录 ----------
  const addMark = useCallback((el: Element) => {
    const rect = el.getBoundingClientRect();
    const ri = reactInfo(el);
    const effW = effectiveWidth();
    const m: Mark = {
      n: (window.__marks?.length || 0) + 1,
      component: ri.component,
      componentChain: ri.chain,
      selector: cssPath(el),
      tag: el.tagName.toLowerCase(),
      cls: (el.getAttribute('class') || '').slice(0, 120),
      text: (el.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 80),
      ariaLabel: el.getAttribute('aria-label') || '',
      rect: { x: Math.round(rect.x), y: Math.round(rect.y), w: Math.round(rect.width), h: Math.round(rect.height) },
      viewport: { w: effW, h: window.innerHeight, isMobile: effW < 768 },
      style: readStyle(el),
      html: el.outerHTML.slice(0, 300),
    };
    const all = [...(window.__marks || []), m];
    window.__marks = all;
    setMarks(all);
    markedElsRef.current.push(el);

    // 每标一个就自动写剪贴板 —— 这样他标完直接粘给我就行，
    // 不用再点一次「复制」。剪贴板写失败无所谓（面板上还能手动复制）。
    try {
      void navigator.clipboard.writeText(JSON.stringify(all, null, 2));
      setCopied(all.length);
    } catch { /* 剪贴板不可用就靠手动复制 */ }
  }, []);

  // ---------- 悬浮高亮 ----------
  useEffect(() => {
    if (!on) { setHover(null); return; }

    const onMove = (e: MouseEvent) => {
      const el = e.target as Element;
      if (!el || el === document.body) return;
      const r = el.getBoundingClientRect();
      const label = `${el.tagName.toLowerCase()}${el.getAttribute('aria-label') ? ' [' + el.getAttribute('aria-label') + ']' : ''} · ${Math.round(r.width)}×${Math.round(r.height)}`;
      hoverRef.current = { x: r.x, y: r.y, w: r.width, h: r.height, label };
      setHover(hoverRef.current);
    };

    const onClick = (e: MouseEvent) => {
      e.preventDefault();
      e.stopPropagation();
      const el = e.target as Element;
      if (el && el !== document.body) addMark(el);
    };

    document.addEventListener('mousemove', onMove, true);
    document.addEventListener('click', onClick, true);
    document.addEventListener('contextmenu', (e) => e.preventDefault(), true);
    return () => {
      document.removeEventListener('mousemove', onMove, true);
      document.removeEventListener('click', onClick, true);
    };
  }, [on, addMark]);

  // ---------- 标记徽章跟随滚动 ----------
  useEffect(() => {
    if (!marks.length) return;
    let raf = 0;
    const tick = () => {
      const layer = badgeLayerRef.current;
      if (layer) {
        const kids = layer.children;
        for (let i = 0; i < kids.length && i < markedElsRef.current.length; i++) {
          const r = markedElsRef.current[i].getBoundingClientRect();
          const k = kids[i] as HTMLElement;
          k.style.transform = `translate(${Math.round(r.x)}px, ${Math.round(r.y)}px)`;
          k.style.display = r.width === 0 && r.height === 0 ? 'none' : 'flex';
        }
      }
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [marks.length]);

  // ---------- 快捷键 ----------
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.altKey && (e.key === 'i' || e.key === 'I')) {
        e.preventDefault();
        // 跟按钮一个行为：开就全开，关就全关
        if (on) { setOn(false); setPanelOpen(false); }
        else { setOn(true); setPanelOpen(true); }
      }
      if (e.key === 'Escape' && on) { setOn(false); setPanelOpen(false); }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [on]);

  // ---------- 开关 ----------
  // 一个按钮一种行为：点一下开（模式 + 面板），再点一下全关。
  // 不做「模式开着但面板关着」这种中间态 —— 少一个状态就少一处让人懵的地方。
  const toggle = () => {
    if (on) { setOn(false); setPanelOpen(false); }
    else { setOn(true); setPanelOpen(true); }
  };

  const closeAll = () => { setOn(false); setPanelOpen(false); };

  const copyAll = async () => {
    const text = JSON.stringify(window.__marks || [], null, 2);
    try {
      await navigator.clipboard.writeText(text);
      setPanelOpen(true);
    } catch { /* 剪贴板不可用就算了，数据我照样能读 */ }
  };

  const clearAll = () => {
    window.__marks = [];
    markedElsRef.current = [];
    setMarks([]);
  };

  return (
    <>
      {/* 悬浮高亮框 */}
      {on && hover && (
        <div
          className="fixed pointer-events-none z-[99998] rounded border-2 border-[#ED6A3B] bg-[#ED6A3B]/10"
          style={{ left: hover.x, top: hover.y, width: hover.w, height: hover.h }}
        >
          <span className="absolute -top-6 left-0 bg-[#ED6A3B] text-white text-[10px] px-1.5 py-0.5 rounded whitespace-nowrap font-mono">
            {hover.label}
          </span>
        </div>
      )}

      {/* 标记徽章层 */}
      <div ref={badgeLayerRef} className="fixed inset-0 pointer-events-none z-[99997]">
        {marks.map(m => (
          <span
            key={m.n}
            className="absolute top-0 left-0 w-5 h-5 rounded-full bg-[#ED6A3B] text-white text-[11px] font-bold flex items-center justify-center shadow-lg"
          >
            {m.n}
          </span>
        ))}
      </div>

      {/* 开关按钮 —— 位置固定，不随面板开合跳动 */}
      <button
        onClick={toggle}
        title="标注模式（Alt+I）—— 开启后点页面上的元素，我就能拿到它的精确信息"
        className={`fixed z-[99999] w-8 h-8 rounded-full text-xs font-bold shadow-lg transition-all
          ${on ? 'bg-[#ED6A3B] text-white scale-110' : 'bg-[#1C1C1C]/70 text-white hover:bg-[#1C1C1C]'}`}
        style={{ right: 12, bottom: 'calc(env(safe-area-inset-bottom) + 12px)' }}
      >
        {on ? '●' : marks.length ? String(marks.length) : '⌖'}
      </button>

      {/* 面板 */}
      {panelOpen && (
        <div className="fixed z-[99999] right-3 bottom-16 w-[300px] max-h-[58vh] bg-white rounded-xl border border-[#E8E4DF] shadow-xl flex flex-col overflow-hidden text-[#1C1C1C]">
          <div className="flex items-center justify-between px-3 py-2 border-b border-[#E8E4DF] bg-[#F7F5F2]">
            <span className="text-xs font-semibold">
              标注 {marks.length ? `(${marks.length})` : ''}
              {copied > 0 && <span className="ml-1.5 text-[10px] font-normal text-[#4E7D6C]">已复制 → 粘给我</span>}
            </span>
            <div className="flex gap-1">
              <button onClick={copyAll} className="px-2 py-0.5 text-[10px] rounded bg-[#ED6A3B] text-white">复制</button>
              <button onClick={clearAll} className="px-2 py-0.5 text-[10px] rounded bg-[#E8E4DF] text-[#5C5C5C]">清空</button>
              <button onClick={closeAll} className="px-1.5 text-[#A0A0A0]" title="关闭">×</button>
            </div>
          </div>

          <div className="flex-1 overflow-y-auto p-2 space-y-1.5 text-[11px]">
            {!marks.length && (
              <p className="text-[#A0A0A0] leading-relaxed p-2">
                {on ? '点页面上任意元素就能标记它。' : '按 Alt+I 或点右下角圆钮开启标注模式。'}
              </p>
            )}
            {marks.map(m => (
              <div key={m.n} className="p-2 rounded-lg bg-[#F7F5F2] border border-[#E8E4DF]">
                <div className="flex items-center gap-1.5 mb-1">
                  <span className="w-4 h-4 rounded-full bg-[#ED6A3B] text-white text-[9px] font-bold flex items-center justify-center">{m.n}</span>
                  <span className="font-mono text-[10px] text-[#ED6A3B] truncate">{m.component || m.tag}</span>
                  <span className="text-[10px] text-[#A0A0A0] ml-auto shrink-0">{m.rect.w}×{m.rect.h}</span>
                </div>
                {m.text && <div className="text-[10px] text-[#5C5C5C] truncate">「{m.text}」</div>}
                {m.ariaLabel && <div className="text-[10px] text-[#A0A0A0] truncate">aria-label: {m.ariaLabel}</div>}
                <div className="text-[9px] text-[#A0A0A0] font-mono truncate mt-0.5">{m.selector}</div>
                <div className="text-[9px] text-[#A0A0A0]">
                  {m.viewport.isMobile ? '手机' : '桌面'} {m.viewport.w}×{m.viewport.h} · {m.rect.x},{m.rect.y}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </>
  );
}
