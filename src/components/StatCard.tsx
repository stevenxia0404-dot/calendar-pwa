// 四宫格清单浮层 —— 点「日程/任务/项目/完成」某一格弹出来的卡片
//
// 跟 DayCard 的区别：
//   DayCard  看的是「某一天有什么」—— 有日期
//   StatCard 看的是「某一类有什么」—— 跨日期的清单
//
// 任务卡和项目卡右上角有「＋」（可在卡片内直接加一条）；
// 日程卡没有 —— 日程是绑定日期的，要加得点日历里的某一天。
//
// 项目卡是**两级**的：
//   第一级 —— 项目列表（名字 + 它下面有几件事）
//   第二级 —— 点项目名进去：项目简介（可手写）+ 这个项目的全部日程
// 项目本身没有日期 —— 它是「这些事属于它」的容器，不是某天发生的事，
// 所以项目不出现在月历划线里。

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

  // ---------- 项目专用 ----------
  /** 项目 id → 它下面的事件 */
  projectItems?: Record<string, ScheduleEvent[]>;
  /** 新建项目（只给名字） */
  onCreateProject?: (name: string) => void;
  /** 改项目名 */
  onRenameProject?: (id: string, name: string) => void;
  /** 改项目简介 */
  onSaveProjectNote?: (id: string, note: string) => void;
  /** 删项目（它下面的事件归为「完成」，不删） */
  onDeleteProject?: (id: string) => void;

  onToggleCompleted?: (id: string) => void;
  onDelete?: (id: string) => void;
  onClose: () => void;
}

export default function StatCard({
  kind, title, items, canAdd, onAdd,
  projectItems, onCreateProject, onRenameProject, onSaveProjectNote, onDeleteProject,
  onToggleCompleted, onDelete, onClose,
}: StatCardProps) {
  const [adding, setAdding] = useState(false);
  const [openProject, setOpenProject] = useState<string | null>(null);

  const isProject = kind === 'project';
  const openTitle = openProject && isProject
    ? (items.find(p => p.id === openProject)?.title || '项目')
    : title;
  const openCount = openProject && isProject
    ? (projectItems?.[openProject] || []).length
    : items.length;

  return (
    // card-panel：跟日期卡同一个宽度（--card-w）。
    // 清单条目多不多只影响高度，内部滚动，宽度永远一样。
    <div className="card-float card-panel rounded-2xl border border-white/70 shadow-[0_8px_40px_rgba(28,28,28,0.16)] max-h-[70vh] overflow-y-auto animate-panel-in">
      <div className="flex justify-between items-center px-4 pt-4 pb-3 sticky top-0 bg-white/95 backdrop-blur-sm z-10">
        <h2 className="font-semibold text-[#1C1C1C]">
          {openTitle}
          <span className="text-[#A0A0A0] font-normal text-sm ml-1.5">{openCount}</span>
        </h2>
        <div className="flex items-center gap-1.5">
          {/* ＋：任务和项目可以直接在卡片里加一条 */}
          {canAdd && !openProject && (
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
        {/* 项目模式：卡内两级 */}
        {isProject ? (
          openProject ? (
            <ProjectDetail
              project={items.find(p => p.id === openProject)}
              events={projectItems?.[openProject] || []}
              onBack={() => setOpenProject(null)}
              onRename={onRenameProject}
              onSaveNote={onSaveProjectNote}
              onDelete={onDeleteProject}
              onToggleCompleted={onToggleCompleted}
              onDeleteEvent={onDelete}
            />
          ) : (
            <ProjectList
              projects={items}
              counts={projectItems}
              adding={adding}
              onOpen={id => setOpenProject(id)}
              onCreate={onCreateProject}
            />
          )
        ) : (
          <>
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
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a2 2 0 00-1-1h-4a2 2 0 00-1 1v3M4 7h16" /></svg>
                        </button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

/* ==================== 项目列表（第一级） ==================== */

function ProjectList({
  projects, counts, adding, onOpen, onCreate,
}: {
  projects: ScheduleEvent[];
  counts?: Record<string, ScheduleEvent[]>;
  adding: boolean;
  onOpen: (id: string) => void;
  onCreate?: (name: string) => void;
}) {
  const [name, setName] = useState('');

  const submit = () => {
    const n = name.trim();
    if (!n || !onCreate) return;
    onCreate(n);
    setName('');
  };

  return (
    <div>
      {adding && (
        <div className="flex gap-2 mb-3">
          <input
            autoFocus
            value={name}
            onChange={e => setName(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); submit(); } }}
            placeholder="项目名，比如「B777 应急带训」"
            className="flex-1 px-3 py-2 border border-[#E8E4DF] rounded-lg text-sm outline-none focus:border-[#1C1C1C]"
          />
          <button onClick={submit}
            className="px-3 py-2 rounded-lg bg-[#ED6A3B] text-white text-sm font-medium hover:bg-[#D45D2E] transition-colors">
            建
          </button>
        </div>
      )}

      {projects.length === 0 ? (
        <p className="text-[#A0A0A0] text-center py-8 text-sm">
          {adding ? '起个名字，项目就建好了' : '还没有项目 —— 点右上角加一个'}
        </p>
      ) : (
        <div className="space-y-1.5">
          {projects.map(p => {
            const n = (counts?.[p.id] || []).length;
            return (
              <button key={p.id} onClick={() => onOpen(p.id)}
                className="w-full flex items-center gap-3 px-3 py-2.5 rounded-xl bg-[#F7F5F2] border border-[#E8E4DF] text-left hover:bg-white/70 transition-colors">
                <span className="w-2 h-2 rounded-full bg-[#7F77DD] shrink-0" aria-hidden />
                <span className="flex-1 min-w-0 font-medium text-[#1C1C1C] truncate">{p.title}</span>
                <span className="text-xs text-[#A0A0A0] shrink-0 tabular-nums">{n} 条</span>
                <svg className="w-4 h-4 text-[#9A9790] shrink-0" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" /></svg>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

/* ==================== 项目详情（第二级） ==================== */

function ProjectDetail({
  project, events, onBack, onRename, onSaveNote, onDelete, onToggleCompleted, onDeleteEvent,
}: {
  project?: ScheduleEvent;
  events: ScheduleEvent[];
  onBack: () => void;
  onRename?: (id: string, name: string) => void;
  onSaveNote?: (id: string, note: string) => void;
  onDelete?: (id: string) => void;
  onToggleCompleted?: (id: string) => void;
  onDeleteEvent?: (id: string) => void;
}) {
  const [name, setName] = useState(project?.title || '');
  const [note, setNote] = useState(project?.raw || '');
  if (!project) return null;

  return (
    <div>
      <button onClick={onBack}
        className="inline-flex items-center gap-1 text-xs text-[#5C5C5C] hover:text-[#ED6A3B] mb-3 transition-colors">
        <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth={2.2} viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M15 19l-7-7 7-7" /></svg>
        全部项目
      </button>

      {/* 项目名 + 简介 —— 显式「保存」。
          为什么不用失焦即存：失焦事件在各种边界下都可能不触发
          （点关闭按钮、点卡片外、快速切换标签），
          改了就丢是最糟的体验。显式保存跟日期卡的编辑表单一个风格。 */}
      <div className="space-y-3 mb-3">
        <div>
          <label className="text-xs text-[#8A8A8A] mb-1 block">项目名</label>
          <input value={name} onChange={e => setName(e.target.value)}
            className="w-full px-3 py-2 border border-[#E8E4DF] rounded-lg text-sm font-medium outline-none focus:border-[#1C1C1C]" />
        </div>

        <div>
          <label className="text-xs text-[#8A8A8A] mb-1 block">项目简介</label>
          <textarea value={note} onChange={e => setNote(e.target.value)}
            placeholder="这个项目是干什么的、进展如何 —— 随便写"
            rows={3}
            className="w-full px-3 py-2 border border-[#E8E4DF] rounded-lg text-sm outline-none focus:border-[#1C1C1C] resize-none" />
        </div>

        <div className="flex justify-end">
          <button onClick={() => {
            const n = name.trim();
            if (n && n !== project.title) onRename?.(project.id, n);
            if (note !== (project.raw || '')) onSaveNote?.(project.id, note);
          }}
            className="px-4 py-1.5 text-sm text-white bg-[#ED6A3B] hover:bg-[#D45D2E] rounded-lg transition-colors">
            保存
          </button>
        </div>
      </div>

      <div className="flex items-center justify-between mb-2">
        <span className="text-xs text-[#A0A0A0]">这个项目下的事</span>
        {onDelete && (
          <button onClick={() => onDelete(project.id)}
            className="text-xs text-[#A65C48] hover:bg-[#FEE2E2] px-2 py-1 rounded-lg transition-colors">
            删掉这个项目
          </button>
        )}
      </div>

      {events.length === 0 ? (
        <p className="text-[#A0A0A0] text-center py-6 text-sm">这个项目下还没有事</p>
      ) : (
        <div className="space-y-2">
          {events.map(e => (
            <div key={e.id}
              className={`p-3 rounded-xl border border-[#E8E4DF] transition-colors ${e.completed ? 'bg-[#F7F5F2]/50' : 'bg-[#F7F5F2]'}`}>
              <div className="flex items-center gap-3">
                {onToggleCompleted && (
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
                    {e.endDate && e.endDate > e.date ? ` → ${e.endDate}` : ''}
                  </div>
                </div>
                {onDeleteEvent && (
                  <button onClick={() => onDeleteEvent(e.id)}
                    className="p-2 text-[#A0A0A0] hover:text-red-500 hover:bg-red-50 rounded-lg transition-colors shrink-0" aria-label="删除">
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a2 2 0 00-1-1h-4a2 2 0 00-1 1v3M4 7h16" /></svg>
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
