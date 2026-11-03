// 设置浮层 —— 点顶栏齿轮弹出来的卡片
//
// 把原来顶栏上散着的按钮收进一张卡：
//   日历订阅（iPhone 自带日历）· 日历导出 · 日历导入 · 日历模板 · 退出
//
// 为什么要收进来：顶栏原来挤了 7 个图标（同步点/刷新/退出/订阅/导出/导入/模板/反馈/帮助），
// 手机上根本认不清哪个是哪个。收进设置后顶栏只剩 5 个，
// 每个都能一眼看出是什么。

'use client';

export interface SettingsCardProps {
  /** 已登录（订阅和退出只在登录后有意义） */
  isOnline: boolean;
  /** 未激活时点这里去激活 */
  onActivate?: () => void;
  onCalSubscribe?: () => void;
  onExport?: () => void;
  onImport?: () => void;
  onTemplate?: () => void;
  onLogout?: () => void;
  onClose: () => void;
}

export default function SettingsCard({
  isOnline, onActivate, onCalSubscribe, onExport, onImport, onTemplate, onLogout, onClose,
}: SettingsCardProps) {
  const items: { key: string; label: string; hint?: string; onClick?: () => void; icon: React.ReactNode; danger?: boolean }[] = [
    // 未激活时把「激活」放在最上面 —— 这是当前最该做的一件事
    ...(!isOnline ? [{
      key: 'activate',
      label: '激活同步',
      hint: '邮箱激活后多设备自动同步',
      onClick: onActivate,
      icon: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2M12 11a4 4 0 100-8 4 4 0 000 8z" /></svg>,
    }] : []),
    {
      key: 'cal',
      label: '订阅到手机日历',
      hint: 'iPhone 相机扫一下，自动同步到系统日历',
      onClick: isOnline ? onCalSubscribe : undefined,
      icon: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="18" rx="2" strokeWidth={2} /><path d="M16 2v4M8 2v4M3 10h18" strokeWidth={2} /></svg>,
    },
    {
      key: 'export',
      label: '导出',
      hint: '存成表格、文本或 Excel',
      onClick: onExport,
      icon: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v2a2 2 0 002 2h12a2 2 0 002-2v-2M7 10l5 5 5-5M12 15V3" /></svg>,
    },
    {
      key: 'import',
      label: '导入',
      hint: '课表 CSV / Excel，逐行可改',
      onClick: onImport,
      icon: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v2a2 2 0 002 2h12a2 2 0 002-2v-2M7 8l5-5 5 5M12 3v12" /></svg>,
    },
    {
      key: 'template',
      label: '下载模板',
      hint: '按格式填好再导入',
      onClick: onTemplate,
      icon: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><rect x="3" y="5" width="18" height="16" rx="1" strokeWidth={2} /><path d="M3 5h18M8 5v16M3 10h18" strokeWidth={2} /></svg>,
    },
    {
      key: 'logout',
      label: '退出登录',
      hint: isOnline ? '这台设备不再同步' : '当前未激活',
      onClick: isOnline ? onLogout : undefined,
      icon: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4M16 17l5-5-5-5M21 12H9" /></svg>,
      danger: true,
    },
  ];

  return (
    // card-panel：跟日期卡、四宫格卡同一个宽度（--card-w）。
    // 加 max-h + overflow-y-auto：设置项将来变多时往纵向长，不撑破屏幕。
    <div className="card-float card-panel rounded-2xl border border-white/70 shadow-[0_8px_40px_rgba(28,28,28,0.16)] max-h-[70vh] overflow-y-auto animate-panel-in">
      {/* 头部吸顶 —— 跟日期卡、四宫格卡一致：
          卡片现在可以内部滚动了，标题不能跟着滚走。 */}
      <div className="flex justify-between items-center px-4 pt-4 pb-2 sticky top-0 bg-white/95 backdrop-blur-sm z-10">
        <h2 className="font-semibold text-[#1C1C1C]">设置</h2>
        <button onClick={onClose}
          className="w-8 h-8 bg-[#F3F1ED] hover:bg-[#E8E4DF] rounded-lg text-[#A0A0A0] flex items-center justify-center transition-colors" aria-label="关闭">
          ×
        </button>
      </div>

      <div className="px-2 pb-3">
        {items.map(it => {
          const disabled = !it.onClick;
          return (
            <button
              key={it.key}
              onClick={() => { if (it.onClick) { it.onClick(); onClose(); } }}
              disabled={disabled}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-left transition-colors ${
                disabled
                  ? 'opacity-40 cursor-default'
                  : it.danger
                  ? 'hover:bg-[#FEE2E2]'
                  : 'hover:bg-[#F3F1ED]'
              }`}
            >
              <span className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 ${
                it.danger ? 'bg-[#FEE2E2] text-[#C2410C]' : 'bg-[#F3F1ED] text-[#5C5C5C]'
              }`}>
                {it.icon}
              </span>
              <span className="min-w-0 flex-1">
                <span className={`block text-sm font-medium ${it.danger ? 'text-[#C2410C]' : 'text-[#1C1C1C]'}`}>{it.label}</span>
                {it.hint && <span className="block text-xs text-[#A0A0A0] mt-0.5 truncate">{it.hint}</span>}
              </span>
            </button>
          );
        })}
      </div>
    </div>
  );
}
