'use client';

// 应用内弹窗 —— 替代原生 confirm() / alert()
//
// 为什么不用原生弹窗：
//   iOS 16+ Safari 在某些条件下会**静默忽略** confirm()，
//   返回 undefined 而不是 true/false —— 于是 `if (!confirm(...)) return;`
//   什么都不发生，用户看到的就是「点了删除，没反应，也没有任何提示」。
//   PWA standalone 模式下同样会被系统级弹窗策略屏蔽。
//
//   而且原生弹窗没法定制样式，跟整套圆角毛玻璃的界面完全不搭。
//
// 用法：
//   const { dialog, ask, tell, close } = useDialog();
//   if (await ask('确定要删除？', '删了就找不回来了', { danger: true })) { ... }
//   await tell('导入失败', '文件读不出来');
//   {dialog && <Dialog {...dialog} onClose={close} />}

import { useCallback, useRef, useState } from 'react';
import type { ReactNode } from 'react';

export interface DialogRequest {
  kind: 'confirm' | 'alert';
  title: string;
  message: string;
  confirmText: string;
  cancelText: string;
  danger: boolean;
}

export interface UseDialog {
  /** 当前要显示的弹窗；null 表示没有 */
  dialog: DialogRequest | null;
  /** 问一句，返回用户是否确定 */
  ask: (
    title: string,
    message: string,
    opts?: { danger?: boolean; confirmText?: string; cancelText?: string },
  ) => Promise<boolean>;
  /** 只告诉用户一件事（没有取消按钮） */
  tell: (title: string, message: string) => Promise<void>;
  /** 关掉弹窗（由 Dialog 组件调用） */
  close: (result: boolean) => void;
}

export function useDialog(): UseDialog {
  const [dialog, setDialog] = useState<DialogRequest | null>(null);
  const resolverRef = useRef<((v: boolean) => void) | null>(null);

  const ask = useCallback((
    title: string,
    message: string,
    opts?: { danger?: boolean; confirmText?: string; cancelText?: string },
  ) => new Promise<boolean>(resolve => {
    resolverRef.current = resolve;
    setDialog({
      kind: 'confirm',
      title,
      message,
      confirmText: opts?.confirmText || '确定',
      cancelText: opts?.cancelText || '取消',
      danger: !!opts?.danger,
    });
  }), []);

  const tell = useCallback((title: string, message: string) => new Promise<void>(resolve => {
    resolverRef.current = () => resolve();
    setDialog({
      kind: 'alert',
      title,
      message,
      confirmText: '知道了',
      cancelText: '',
      danger: false,
    });
  }), []);

  const close = useCallback((result: boolean) => {
    const r = resolverRef.current;
    resolverRef.current = null;
    setDialog(null);
    r?.(result);
  }, []);

  return { dialog, ask, tell, close };
}

/* ==================== 弹窗本体 ==================== */

export function Dialog({ request, onClose }: { request: DialogRequest; onClose: (result: boolean) => void }) {
  return (
    <div
      className="fixed inset-0 z-[90] flex items-center justify-center bg-black/35 backdrop-blur-sm p-6"
      onClick={() => onClose(false)}
    >
      <div
        className="card-float rounded-2xl border border-white/70 shadow-[0_8px_40px_rgba(28,28,28,0.16)] w-[var(--card-w)] max-w-full px-5 py-5 animate-panel-in"
        onClick={e => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-label={request.title}
      >
        <h3 className="text-base font-semibold text-[#1C1C1C] mb-1.5">{request.title}</h3>
        {request.message && (
          <p className="text-sm text-[#5C5C5C] leading-relaxed whitespace-pre-line">{request.message}</p>
        )}
        <div className="flex gap-2 mt-4">
          {request.kind === 'confirm' && (
            <button onClick={() => onClose(false)}
              className="flex-1 h-10 rounded-lg border border-[#E8E4DF] text-sm text-[#5C5C5C] hover:bg-[#F3F1ED] transition-colors">
              {request.cancelText}
            </button>
          )}
          <button onClick={() => onClose(true)}
            className={`flex-1 h-10 rounded-lg text-sm font-semibold text-white transition-colors ${
              request.danger ? 'bg-[#A65C48] hover:bg-[#8E4C3D]' : 'bg-[#ED6A3B] hover:bg-[#D45D2E]'
            }`}>
            {request.confirmText}
          </button>
        </div>
      </div>
    </div>
  );
}

/** 把弹窗挂到页面里 —— 在 page.tsx 里调用一次就行 */
export function DialogHost({ dialog, close }: { dialog: DialogRequest | null; close: (r: boolean) => void }): ReactNode {
  if (!dialog) return null;
  return <Dialog request={dialog} onClose={close} />;
}
