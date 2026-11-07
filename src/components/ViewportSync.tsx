// 把「真实可视区」同步成 CSS 变量。
//
// ---------------------------------------------------------------------------
// **为什么需要它**（iOS PWA 的一个硬约束）
//
// `100vh` / `100dvh` 在 iOS 上都不是「用户此刻看得见的高度」：
//
// · `100vh` = **大视口** —— 按地址栏/工具栏**收起来**时算的。
//   比真实可见区高出一截。文档一旦比可视区高，手指就能滑动页面。
//   表现就是「底部输入框纹丝不动、其它地方要滑才看全」：
//   输入框是 position:fixed，钉在视口里，永远不参与文档滚动。
//
// · `100dvh` = **动态视口** —— 会跟着地址栏收放变。
//   PWA 全屏模式下没有地址栏，所以它约等于 100vh，同样偏高。
//   键盘弹出时它也**不变**（键盘是覆盖，不是挤压）。
//
// · `height:100%` 相对 ICB（初始包含块），在 iOS 上也可能等于大视口。
//
// **`window.visualViewport.height` 是唯一可靠的数字** ——
// 浏览器明确告诉你「用户此刻真正看得见多少像素」。
// 键盘弹出时它立刻变小，地址栏收放时它跟着变。
//
// ---------------------------------------------------------------------------
//
// **同步三个变量**
//
// · `--app-vh`  可视区高度 → 应用外壳的高度
// · `--app-vtop` 可视区顶部偏移 → 键盘弹出时 iOS 会把文档往下推，
//   外壳要跟着偏移，否则顶栏会被推到看不见的地方
// · `--app-kb`  键盘高度 → 底部输入区要往上让
//
// 写成 CSS 变量而不是 React state ——
// 每次 resize/scroll 都重渲染整棵页面树太浪费，变量交给 CSS 处理最省。
//
// ---------------------------------------------------------------------------

'use client';

import { useEffect } from 'react';

export default function ViewportSync() {
  useEffect(() => {
    const root = document.documentElement;
    const vv = window.visualViewport;

    const apply = () => {
      if (!vv) {
        // 老浏览器没有 visualViewport —— 退回 innerHeight
        root.style.setProperty('--app-vh', `${window.innerHeight}px`);
        root.style.setProperty('--app-vtop', '0px');
        root.style.setProperty('--app-kb', '0px');
        return;
      }
      const vh = vv.height;
      const vtop = vv.offsetTop;
      // 键盘高度 = 布局视口高 − 可视区高 − 顶部偏移
      const kb = Math.max(0, window.innerHeight - vh - vtop);
      root.style.setProperty('--app-vh', `${Math.round(vh)}px`);
      root.style.setProperty('--app-vtop', `${Math.round(vtop)}px`);
      root.style.setProperty('--app-kb', `${Math.round(kb)}px`);
    };

    apply();

    if (!vv) {
      window.addEventListener('resize', apply);
      return () => window.removeEventListener('resize', apply);
    }
    vv.addEventListener('resize', apply);
    vv.addEventListener('scroll', apply);
    return () => {
      vv.removeEventListener('resize', apply);
      vv.removeEventListener('scroll', apply);
    };
  }, []);

  return null;
}
