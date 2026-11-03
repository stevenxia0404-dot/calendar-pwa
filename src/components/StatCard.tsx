// 四宫格清单浮层 —— 点「日程/任务/项目/完成」某一格弹出来的卡片
//
// 跟 DayCard 的区别：
//   DayCard  看的是「某一天有什么」—— 有日期
//   StatCard 看的是「某一类有什么」—— 跨日期的清单
//
// 任务卡和项目卡右上角有「＋」（可在卡片内直接加一条）；
// 日程卡没有 —— 日程是绑定日期的，要加得点日历里的某一天。

'use client';

import { useState } from 'react';
import type { ScheduleEvent } from '@/lib/scheduleTypes';

export type StatKind = 'event' | 'task' | 'project' | 'completed';

export interface StatCardProps {
  kind: StatKind;
  title: string;
  items: ScheduleEvent[];
  /** 能不能在卡片里直接加一条 —— 任务/项目可以，日程不行 */
  canAdd: boolean;
  onAdd?: () => void;
  onToggleCompleted?: (id: string) => void;
  onDelete?: (id: string) => void;
  onClose: () => void;
}

export default function StatCard({
  kind, title, items, canAdd, onAdd, onToggleCompleted, onDelete, onClose,
}: StatCardProps) {
  const [adding, setAdding] = useState(false);

  return (
    // card-panel：跟日期卡同一个宽度（--card-w）。
    // 清单条目多不多只影响高度，内部滚动，宽度永远一样。
    <div className="card-float card-panel rounded-2xl border border-white/70 shadow-[0_8px_40px_rgba(28,28,28,0.16)] max-h-[70vh] overflow-y-auto animate-panel-in">
      <div className="flex justify-between items-center px-4 pt-4 pb-3 sticky top-0 bg-white/95 backdrop-blur-sm">
        <h2 className="font-semibold text-[#1C1C1C]">
          {title}
          <span className="text-[#A0A0A0] font-normal text-sm ml-1.5">{items.length}</span>
        </h2>
        <div className="flex items-center gap-1.5">
          {/* ＋：任务和项目可以直接在卡片里加一条 */}
          {canAdd && (
            <button onClick={() => { setAdding(true); onAdd?.(); }}
              className="w-8 h-8 rounded-lg bg-[#ED6A3B] hover:bg-[#D45D2E] text-white flex items-center justify-center transition-colors"
              aria-label="添加一条" title="添加一条">
              <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth={2.4} viewBox="0 0 24 24"><path strokeLinecap="round" d="M12 5v14M5 12h14" /></svg>
            </button>
          )}
          <button onClick={onClose}
            className="w-8 h-8 bg-[#F3F1ED] hover:bg-[#E8E4DF] rounded-lg text-[#A0A0A0] flex items-center justify-center transition-colors" aria-label="关闭">
            ×
          </button>
        </div>
      </div>

      <div className="px-4 pb-4">
        {adding && (
          <p className="text-xs text-[#8A6D3B] bg-[#FFF9EC] border border-[#F0E2C0] rounded-lg px-3 py-2 mb-3">
            在下面的输入框说一句话，就会加到这里
          </p>
        )}

        {items.length === 0 ? (
          <p className="text-[#A0A0A0] text-center py-8 text-sm">
            {adding ? '在下面输入框说一句试试' : '还没有内容'}
          </p>
        ) : (
          <div className="space-y-2">
            {items.map(e => (
              <div key={e.id}
                className={`p-3 rounded-xl border border-[#E8E4DF] transition-colors ${e.completed ? 'bg-[#F7F5F2]/50' : 'bg-[#F7F5F2]'}`}>
                <div className="flex items-center gap-3">
                  {onToggleCompleted && kind !== 'event' && (
                    <button onClick={() => onToggleCompleted(e.id)}
                      className={`w-5 h-5 rounded-full border-2 flex items-center justify-center shrink-0 transition-all ${
                        e.completed ? 'bg-[#ED6A3B] border-[#ED6A3B]' : 'border-[#D9D4CF] hover:border-[#ED6A3B]'
                      }`}
                      aria-label={e.completed ? '取消完成' : '标记完成'}>
                      {e.completed && (
                        <svg className="w-3 h-3 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 13l4 4L19 7" />
                        </svg>
                      )}
                    </button>
                  )}
                  <div className="flex-1 min-w-0">
                    <div className={`font-medium truncate ${e.completed ? 'line-through text-[#A0A0A0]' : 'text-[#1C1C1C]'}`}>
                      {e.title}
                    </div>
                    <div className="text-xs text-[#A0A0A0] mt-0.5 truncate">
                      {e.date}{e.time ? ` ${e.time}` : ''}
                      {(e.location || e.people) ? ` · ${e.location}${e.location && e.people ? ' · ' : ''}${e.people}` : ''}
                    </div>
                  </div>
                  {onDelete && (
                    <button onClick={() => onDelete(e.id)}
                      className="p-2 text-[#A0A0A0] hover:text-red-500 hover:bg-red-50 rounded-lg transition-colors shrink-0" aria-label="删除">
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a2 2 0 00-1-1h-4a2 2 0 00-1 1v3M4 7h16" /></svg>
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
