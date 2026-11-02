// 日期详情浮层 —— 点日历某一天弹出来的卡片
//
// 这段逻辑原来在 page.tsx 里，是「桌面端右栏明细卡」。
// 现在改成浮层：点哪天弹哪天的卡片，下面的内容全部模糊。
//
// 复用了原来那套编辑能力（改事项/日期/时间/地点/人员、勾完成、删除），
// 一行逻辑没改 —— 只是从「右栏」搬到了「居中浮层」。

'use client';

import type { ScheduleEvent } from '@/lib/scheduleTypes';

export interface DayCardProps {
  date: string;
  dayEvents: ScheduleEvent[];
  dayTasks: ScheduleEvent[];
  editingEventId: string | null;
  editForm: {
    title: string; date: string; time: string; endTime: string;
    location: string; people: string;
  };
  onEditFormChange: (form: DayCardProps['editForm']) => void;
  onStartEdit: (e: ScheduleEvent) => void;
  onCancelEdit: () => void;
  onSaveEdit: () => void;
  onToggleCompleted: (id: string) => void;
  onDelete: (id: string) => void;
  onClose: () => void;
}

export default function DayCard({
  date, dayEvents, dayTasks, editingEventId, editForm,
  onEditFormChange, onStartEdit, onCancelEdit, onSaveEdit,
  onToggleCompleted, onDelete, onClose,
}: DayCardProps) {
  const set = (patch: Partial<DayCardProps['editForm']>) =>
    onEditFormChange({ ...editForm, ...patch });

  return (
    <div className="card-float rounded-2xl border border-white/70 shadow-[0_8px_40px_rgba(28,28,28,0.16)] w-full max-w-sm max-h-[70vh] overflow-y-auto animate-panel-in">
      <div className="flex justify-between items-center px-4 pt-4 pb-3 sticky top-0 bg-white/95 backdrop-blur-sm">
        <h2 className="font-semibold text-[#1C1C1C]">{date} 的安排</h2>
        <button onClick={onClose}
          className="w-8 h-8 bg-[#F3F1ED] hover:bg-[#E8E4DF] rounded-lg text-[#A0A0A0] flex items-center justify-center transition-colors" aria-label="关闭">
          ×
        </button>
      </div>

      <div className="px-4 pb-4">
        {dayEvents.length === 0 && dayTasks.length === 0 ? (
          <p className="text-[#A0A0A0] text-center py-8 text-sm">
            这一天还没有安排 —— 在下面说一句话就能加进来
          </p>
        ) : (
          <div className="space-y-3">
            {/* 定时日程 */}
            {dayEvents.map(e => (
              <div key={e.id} className="p-3 bg-[#F7F5F2] rounded-xl border border-[#E8E4DF]">
                {editingEventId === e.id ? (
                  <EditForm form={editForm} set={set} onCancel={onCancelEdit} onSave={onSaveEdit} showTime />
                ) : (
                  <div className="flex items-center gap-3">
                    <span className="bg-[#ED6A3B] text-white text-sm px-3 py-1.5 rounded-lg font-mono font-semibold min-w-[60px] text-center">
                      {e.time}{e.endTime ? `-${e.endTime}` : ''}
                    </span>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-1.5">
                        <div className="font-medium text-[#1C1C1C] truncate">{e.title}</div>
                        {e.dateConfirmed === 0 && <PendingBadge onClick={() => onStartEdit(e)} />}
                      </div>
                      {(e.location || e.people) && (
                        <div className="text-xs text-[#A0A0A0] mt-0.5 truncate">
                          {e.location}{e.location && e.people ? ' · ' : ''}{e.people}
                        </div>
                      )}
                    </div>
                    <RowActions onEdit={() => onStartEdit(e)} onDelete={() => onDelete(e.id)} />
                  </div>
                )}
              </div>
            ))}

            {/* 无时间的记录 */}
            {dayTasks.map(e => (
              <div key={e.id} className={`p-3 rounded-xl border border-[#E8E4DF] transition-colors ${e.completed ? 'bg-[#F7F5F2]/50' : 'bg-[#F7F5F2]'}`}>
                {editingEventId === e.id ? (
                  <EditForm form={editForm} set={set} onCancel={onCancelEdit} onSave={onSaveEdit} />
                ) : (
                  <div className="flex items-center gap-3">
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
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-1.5">
                        <div className={`font-medium truncate ${e.completed ? 'line-through text-[#A0A0A0]' : 'text-[#1C1C1C]'}`}>{e.title}</div>
                        {e.dateConfirmed === 0 && <PendingBadge onClick={() => onStartEdit(e)} />}
                      </div>
                      {(e.location || e.people) && (
                        <div className={`text-xs mt-0.5 truncate ${e.completed ? 'line-through text-[#C0BDB8]' : 'text-[#A0A0A0]'}`}>
                          {e.location}{e.location && e.people ? ' · ' : ''}{e.people}
                        </div>
                      )}
                    </div>
                    <RowActions onEdit={() => onStartEdit(e)} onDelete={() => onDelete(e.id)} />
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

/* ==================== 子组件 ==================== */

function PendingBadge({ onClick }: { onClick: () => void }) {
  return (
    <button onClick={onClick}
      className="shrink-0 text-[10px] text-[#ED6A3B] bg-[#FFF5F0] hover:bg-[#FFE8DC] rounded px-1.5 py-0.5 transition-colors"
      title="日期没认出来，改一下">
      待确认
    </button>
  );
}

function RowActions({ onEdit, onDelete }: { onEdit: () => void; onDelete: () => void }) {
  return (
    <div className="flex gap-1 shrink-0">
      <button onClick={onEdit} className="p-2 text-[#A0A0A0] hover:text-[#ED6A3B] hover:bg-[#FFF5F0] rounded-lg transition-colors" aria-label="编辑">
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2.828 2.828 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" /></svg>
      </button>
      <button onClick={onDelete} className="p-2 text-[#A0A0A0] hover:text-red-500 hover:bg-red-50 rounded-lg transition-colors" aria-label="删除">
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a2 2 0 00-1-1h-4a2 2 0 00-1 1v3M4 7h16" /></svg>
      </button>
    </div>
  );
}

/** 编辑表单 —— 日程和任务共用，只是日程多了时间两个字段 */
function EditForm({
  form, set, onCancel, onSave, showTime,
}: {
  form: DayCardProps['editForm'];
  set: (patch: Partial<DayCardProps['editForm']>) => void;
  onCancel: () => void;
  onSave: () => void;
  showTime?: boolean;
}) {
  const inputCls = 'w-full px-3 py-2 border border-[#E8E4DF] rounded-lg text-sm outline-none focus:border-[#1C1C1C]';
  return (
    <div className="space-y-3">
      <div>
        <label className="text-xs text-[#A0A0A0] mb-1 block">事项</label>
        <input type="text" value={form.title} onChange={ev => set({ title: ev.target.value })}
          className={inputCls} />
      </div>
      <div>
        <label className="text-xs text-[#A0A0A0] mb-1 block">日期</label>
        <input type="date" title="日期" value={form.date} onChange={ev => set({ date: ev.target.value })}
          className={inputCls} />
      </div>
      {showTime && (
        <div className="flex gap-3">
          <div className="flex-1">
            <label className="text-xs text-[#A0A0A0] mb-1 block">开始时间</label>
            <input type="time" title="开始时间" value={form.time} onChange={ev => set({ time: ev.target.value })}
              className={inputCls} />
          </div>
          <div className="flex-1">
            <label className="text-xs text-[#A0A0A0] mb-1 block">结束时间</label>
            <input type="time" title="结束时间" value={form.endTime} onChange={ev => set({ endTime: ev.target.value })}
              className={inputCls} />
          </div>
        </div>
      )}
      <div className="flex gap-3">
        <div className="flex-1">
          <label className="text-xs text-[#A0A0A0] mb-1 block">地点</label>
          <input type="text" value={form.location} onChange={ev => set({ location: ev.target.value })}
            className={inputCls} placeholder="教室/会议室" />
        </div>
        <div className="flex-1">
          <label className="text-xs text-[#A0A0A0] mb-1 block">人员</label>
          <input type="text" value={form.people} onChange={ev => set({ people: ev.target.value })}
            className={inputCls} placeholder="老师/同学" />
        </div>
      </div>
      <div className="flex gap-2 justify-end">
        <button onClick={onCancel}
          className="px-4 py-1.5 text-sm text-[#5C5C5C] bg-[#E8E4DF] rounded-lg hover:bg-[#D9D4CF] transition-colors">取消</button>
        <button onClick={onSave} className="px-4 py-1.5 text-sm text-white bg-[#ED6A3B] rounded-lg hover:bg-[#D45D2E] transition-colors">保存</button>
      </div>
    </div>
  );
}
