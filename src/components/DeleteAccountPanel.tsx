// 注销账号面板 —— 删掉云端的全部数据（不可逆）
//
// ---------------------------------------------------------------------------
// **为什么单独做一个组件，而不是扩展 Dialog**
//
// Dialog 是全局弹窗（导出/导入/帮助/反馈都在用）。
// 要在它里面加「输入框」就得改它的结构 —— 那是**结构层**改动，
// 会波及所有弹窗，风险不成比例。
//
// 而注销是**独立流程**：只有「输入邮箱确认」这一个交互，
// 自包含一个面板更安全，也不动别人的东西。
//
// ---------------------------------------------------------------------------
// **为什么要「输入邮箱确认」而不是「点一下确定」**
//
// 注销是**不可逆**操作：云端数据删掉就找不回来了。
// 一个手滑就永久丢数据 —— 「点一下确定」不够。
// 要用户亲手打一遍邮箱，打错就打不对 —— 这是防误操作的最低成本手段。
//
// ---------------------------------------------------------------------------

'use client';

import { useState } from 'react';

export interface DeleteAccountPanelProps {
  /** 当前登录用户的邮箱 —— 要用户输入它来确认 */
  email: string;
  /** 关掉面板 */
  onClose: () => void;
  /** 执行注销（抛错 = 失败，组件自己处理） */
  onConfirm: () => Promise<void>;
}

export default function DeleteAccountPanel({ email, onClose, onConfirm }: DeleteAccountPanelProps) {
  const [input, setInput] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  // 大小写不敏感 + 去掉首尾空格 —— 用户从邮件里复制粘贴常带空格
  const normalized = input.trim().toLowerCase();
  const target = email.trim().toLowerCase();
  const match = normalized.length > 0 && normalized === target;

  const submit = async () => {
    if (!match || busy) return;
    setBusy(true);
    setError('');
    try {
      await onConfirm();
      // 成功 —— 面板会被父组件关掉（token 清空后设置卡也用不上了）
    } catch (e) {
      setError(e instanceof Error ? e.message : '注销失败，请稍后重试');
      setBusy(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-[80] flex items-center justify-center bg-black/40 backdrop-blur-sm p-6"
      onClick={() => { if (!busy) onClose(); }}
    >
      <div
        className="card-float rounded-2xl border border-white/70 shadow-[0_8px_40px_rgba(28,28,28,0.16)] w-[var(--card-w)] max-w-full px-5 py-5 animate-panel-in"
        onClick={e => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-label="注销账号"
      >
        <div className="flex items-start gap-3 mb-3">
          <span className="w-9 h-9 rounded-lg bg-[#FEE2E2] text-[#A32D2D] flex items-center justify-center shrink-0">
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
            </svg>
          </span>
          <div className="min-w-0">
            <h3 className="text-base font-semibold text-[#1C1C1C]">注销账号并删除云端数据</h3>
            <p className="text-xs text-[#A0A0A0] mt-0.5">这一步不可撤销</p>
          </div>
        </div>

        <div className="text-sm text-[#5C5C5C] leading-relaxed space-y-2 mb-4">
          <p>将永久删除 <b className="text-[#1C1C1C]">{email}</b> 名下的：</p>
          <ul className="text-xs space-y-1">
            <li className="flex gap-2"><span className="text-[#E24B4A]">·</span><span>云端全部日程记录</span></li>
            <li className="flex gap-2"><span className="text-[#E24B4A]">·</span><span>账号本身</span></li>
            <li className="flex gap-2"><span className="text-[#E24B4A]">·</span><span>登录凭证与日历订阅</span></li>
          </ul>
          <p className="text-xs text-[#A0A0A0] pt-1">
            这台设备上的本地数据仍会保留，但之后再登录就是新账号了。
          </p>
        </div>

        <label className="block">
          <span className="text-xs text-[#8A8A8A]">请输入邮箱以确认</span>
          <input
            type="email"
            inputMode="email"
            autoComplete="email"
            autoCapitalize="none"
            autoCorrect="off"
            value={input}
            onChange={e => { setInput(e.target.value); setError(''); }}
            onKeyDown={e => { if (e.key === 'Enter' && match && !busy) submit(); }}
            placeholder={email}
            className="mt-1 w-full h-10 px-3 rounded-lg border border-[#E8E4DF] bg-white text-sm text-[#1C1C1C] outline-none focus:border-[#ED6A3B] transition-colors"
            disabled={busy}
          />
        </label>

        {error && (
          <p className="mt-2 text-xs text-[#E24B4A] leading-relaxed">{error}</p>
        )}
        {!match && input.trim().length > 0 && !error && (
          <p className="mt-2 text-xs text-[#A0A0A0]">邮箱不匹配</p>
        )}

        <div className="flex gap-2 mt-4">
          <button
            onClick={onClose}
            disabled={busy}
            className="flex-1 h-10 rounded-lg border border-[#E8E4DF] text-sm text-[#5C5C5C] hover:bg-[#F3F1ED] transition-colors disabled:opacity-40"
          >
            取消
          </button>
          <button
            onClick={submit}
            disabled={!match || busy}
            className="flex-1 h-10 rounded-lg text-sm font-semibold text-white bg-[#A32D2D] hover:bg-[#791F1F] transition-colors disabled:opacity-35 disabled:cursor-not-allowed"
          >
            {busy ? '注销中…' : '永久删除'}
          </button>
        </div>
      </div>
    </div>
  );
}
