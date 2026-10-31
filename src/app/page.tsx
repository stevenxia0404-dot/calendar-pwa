'use client';

import { useState, useEffect } from 'react';
import { ChevronLeft, ChevronRight, Download, LogOut, Mail, RefreshCw, Upload } from 'lucide-react';


import WeekView from '@/components/WeekView';
import InputArea from '@/components/InputArea';
import { ParsedResult } from '@/lib/dateParser';
import { toDateString as weekToDateString, weekDates } from '@/lib/weekLogic';

// ==================== 配置 ====================

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'https://schedule-api.boluomate.com';

// 导入文件大小上限。课表正常在几百 KB 以内，5MB 足够，
// 同时能挡住构造出来的超大文件把浏览器内存拖垮。
const MAX_IMPORT_FILE_BYTES = 5 * 1024 * 1024;

// ==================== 工具函数 ====================

function formatLocalDate(date: Date): string {
  const y = date.getFullYear();
  const m = String(date.getMonth() + 1).padStart(2, '0');
  const d = String(date.getDate()).padStart(2, '0');
  return `${y}-${m}-${d}`;
}

function parseCsvLine(line: string): string[] {
  const cells: string[] = [];
  let cur = '', inQuote = false;
  for (const ch of line) {
    if (ch === '"') { inQuote = !inQuote; }
    else if (ch === ',' && !inQuote) { cells.push(cur.trim()); cur = ''; }
    else { cur += ch; }
  }
  cells.push(cur.trim());
  return cells;
}

// 单元格值转文本。
// Excel 里的「真日期」是日期序列号，解析出来是 Date 对象，
// 直接 String() 会得到 "Mon Nov 02 2026 ..." 这种乱码，导入必失败。
function cellToText(c: unknown): string {
  if (c === null || c === undefined) return '';
  if (c instanceof Date) {
    // 用 UTC 分量还原：Excel 日期序列号本身不带时区，解析库按 UTC 解释，
    // 若用本地分量，在负时区会把纯日期偏成前一天。
    const y = c.getUTCFullYear();
    const m = String(c.getUTCMonth() + 1).padStart(2, '0');
    const d = String(c.getUTCDate()).padStart(2, '0');
    return `${y}-${m}-${d}`;
  }
  if (typeof c === 'string') {
    // 兜底：某些解析配置下日期会直接给 ISO 字符串
    const iso = c.match(/^(\d{4}-\d{2}-\d{2})T/);
    if (iso) return iso[1];
  }
  return String(c);
}

function extractTime(text: string) {
  let isPM = text.includes('下午') || text.includes('晚上');
  let hour = 9, minute = 0;
  let matched = false;

  // 中文数字→阿拉伯数字
  const cnNum: Record<string, number> = { '零':0, '一':1, '二':2, '两':2, '三':3, '四':4, '五':5, '六':6, '七':7, '八':8, '九':9, '十':10 };
  function toNum(s: string): number {
    if (/^\d+$/.test(s)) return parseInt(s);
    if (s.length === 1) return cnNum[s] ?? 0;
    if (s.startsWith('十')) return 10 + (cnNum[s[1]] ?? 0);
    if (s.endsWith('十')) return (cnNum[s[0]] ?? 0) * 10;
    const [a, b] = s.split('十');
    return (cnNum[a] ?? 0) * 10 + (cnNum[b] ?? 0);
  }

  let m = text.match(/([\d一二三四五六七八九十两零]{1,3})\s*点(?:\s*([\d零一二三四五六七八九十两半]+)\s*([分刻]?))?/);
  if (m) {
    hour = toNum(m[1]);
    if (m[2] === '半') minute = 30;
    else if (m[3] === '刻') minute = Math.min(toNum(m[2]) * 15, 59);
    else if (m[2]) minute = toNum(m[2]);
    matched = true;
  } else {
    m = text.match(/(\d{1,2})\s*[:：]\s*(\d{2})/);
    if (m) { hour = parseInt(m[1]); minute = parseInt(m[2]); matched = true; isPM = false; }
  }

  if (matched && isPM && hour < 12) hour += 12;
  if (hour > 23) hour = 23;
  if (minute > 59) minute = 59;

  return {
    str: `${String(hour).padStart(2, '0')}:${String(minute).padStart(2, '0')}`,
    hour, minute, isPM, matched
  };
}

function parseSmartDate(text: string): Date | null {
  const today = new Date(); today.setHours(0, 0, 0, 0);

  if (text.includes('今天')) return new Date(today);
  if (text.includes('明天')) { const d = new Date(today); d.setDate(d.getDate() + 1); return d; }
  if (text.includes('后天')) { const d = new Date(today); d.setDate(d.getDate() + 2); return d; }
  if (text.includes('大后天')) { const d = new Date(today); d.setDate(d.getDate() + 3); return d; }

  const daysLater = text.match(/(\d+)天后/);
  if (daysLater) { const d = new Date(today); d.setDate(d.getDate() + parseInt(daysLater[1])); return d; }

  const weekDays = ['一', '二', '三', '四', '五', '六', '日', '天'];
  const nextWeek = text.match(/下周([一二三四五六日天])/);
  if (nextWeek) {
    const target = weekDays.indexOf(nextWeek[1]) + 1;
    const cur = today.getDay(); const curAdj = cur === 0 ? 7 : cur;
    const d = new Date(today); d.setDate(d.getDate() + (7 - curAdj) + target); return d;
  }

  const thisWeek = text.match(/本周([一二三四五六日天])/);
  if (thisWeek) {
    const target = weekDays.indexOf(thisWeek[1]) + 1;
    const cur = today.getDay(); const curAdj = cur === 0 ? 7 : cur;
    let add = target - curAdj; if (add < 0) add += 7;
    const d = new Date(today); d.setDate(d.getDate() + add); return d;
  }

  const nextMonth = text.match(/下个月(\d{1,2})[号日]/);
  if (nextMonth) {
    const d = new Date(today); d.setMonth(d.getMonth() + 1); d.setDate(parseInt(nextMonth[1])); return d;
  }

  const dateMatch = text.match(/(\d{1,2})月(\d{1,2})[号日]/);
  if (dateMatch) {
    const d = new Date(today.getFullYear(), parseInt(dateMatch[1]) - 1, parseInt(dateMatch[2]));
    if (d < today) d.setFullYear(d.getFullYear() + 1);
    return d;
  }

  return null;
}

// ==================== API 函数 ====================

async function api(path: string, options: RequestInit = {}, token?: string | null) {
  const headers: Record<string, string> = { 'Content-Type': 'application/json', ...options.headers as Record<string, string> };
  if (token) headers['Authorization'] = `Bearer ${token}`;

  const res = await fetch(`${API_BASE}${path}`, { ...options, headers });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

// ==================== 类型 ====================

interface ScheduleEvent {
  id: string;
  title: string;
  date: string;
  time: string;
  endTime: string;
  location: string;
  people: string;
  raw: string;
  updatedAt: number;
  type: 'event' | 'task';
  completed: boolean;
  /** 0 = 规则没解出日期，待用户确认；1 = 已确认 */
  dateConfirmed?: 0 | 1;
}

interface User { id: number; email: string; role?: 'family' | 'user'; }

// ==================== 主组件 ====================

export default function Home() {
  // 日程状态
  const [events, setEvents] = useState<ScheduleEvent[]>([]);
  const [detailDate, setDetailDate] = useState<string | null>(null);
  const [editingEventId, setEditingEventId] = useState<string | null>(null);
  const [editForm, setEditForm] = useState({ title: '', date: '', time: '', endTime: '', location: '', people: '' });

  // v4.0：周视图锚点（周内任意一天即可）与窄屏判定
  const [weekAnchor, setWeekAnchor] = useState(new Date());
  const [isNarrow, setIsNarrow] = useState(false);

  // 认证状态
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [isSyncing, setIsSyncing] = useState(false);
  const [offline, setOffline] = useState(false);

  // 激活弹窗
  const [showActivate, setShowActivate] = useState(false);
  const [activateStep, setActivateStep] = useState<'email' | 'code'>('email');
  const [activateEmail, setActivateEmail] = useState('');
  const [activateCode, setActivateCode] = useState('');
  const [activateError, setActivateError] = useState('');
  const [activateLoading, setActivateLoading] = useState(false);
  const [activateSuccess, setActivateSuccess] = useState(false);
  const [showCalModal, setShowCalModal] = useState(false);
  const [icalCopied, setIcalCopied] = useState(false);
  const [showVersionModal, setShowVersionModal] = useState(false);

  // 版本更新弹窗（首次访问展示一次）
  useEffect(() => {
    const seen = localStorage.getItem('schedule_version_seen');
    if (seen !== 'v4.0') setShowVersionModal(true);
  }, []);

  const dismissVersionModal = () => {
    localStorage.setItem('schedule_version_seen', 'v4.0');
    setShowVersionModal(false);
  };

  const [showFeedback, setShowFeedback] = useState(false);
  const [feedbackText, setFeedbackText] = useState('');
  const [feedbackSent, setFeedbackSent] = useState(false);
  const [showHelp, setShowHelp] = useState(false);
  const [showImportModal, setShowImportModal] = useState(false);
  const [importText, setImportText] = useState('');
  const [importPreview, setImportPreview] = useState<ScheduleEvent[] | null>(null);
  const [importGroups, setImportGroups] = useState<{ id: string; name: string; count: number; time: string }[]>([]);

  const submitFeedback = async () => {
    if (!feedbackText.trim()) return;
    try {
      await api('/feedback', { method: 'POST', body: JSON.stringify({ text: feedbackText, email: user?.email || '' }) }, token);
      setFeedbackSent(true);
      setTimeout(() => { setShowFeedback(false); setFeedbackSent(false); setFeedbackText(''); }, 2000);
    } catch { /* ignore */ }
  };

  const isOnline = !!user && !!token;

  // 窄屏判定：手机上降级为单日竖向时间轴（每列 50px 的七列没法看）
  useEffect(() => {
    const check = () => setIsNarrow(window.innerWidth < 768);
    check();
    window.addEventListener('resize', check);
    return () => window.removeEventListener('resize', check);
  }, []);

  // ==================== 初始化 ====================

  useEffect(() => {
    const saved = localStorage.getItem('schedule_events');
    if (saved) { try { setEvents(JSON.parse(saved)); } catch { /* ignore */ } }

    const savedToken = localStorage.getItem('schedule_token');
    if (savedToken) setToken(savedToken);

    const savedGroups = localStorage.getItem('schedule_import_groups');
    if (savedGroups) { try { setImportGroups(JSON.parse(savedGroups)); } catch { /* ignore */ } }
  }, []);

  useEffect(() => {
    localStorage.setItem('schedule_events', JSON.stringify(events));
  }, [events]);

  // 自动验证 token
  useEffect(() => {
    if (!token) { setUser(null); return; }
    api('/auth/me', {}, token)
      .then(d => setUser(d.user))
      .catch(() => { localStorage.removeItem('schedule_token'); setToken(null); setUser(null); });
  }, [token]);

  // 登录后自动同步
  useEffect(() => {
    if (!isOnline) return;
    const lastSync = localStorage.getItem('schedule_last_sync');
    syncFromCloud(lastSync || undefined);
  }, [isOnline]);

  // 自动轮询（全量同步，先推后拉，无竞态）
  useEffect(() => {
    if (!isOnline) return;
    const timer = setInterval(() => {
      syncFromCloud();
    }, 30000);
    return () => clearInterval(timer);
  }, [isOnline]);

  // ==================== 同步 ====================

  const syncFromCloud = async (since?: string) => {
    if (!token) return false;
    setIsSyncing(true);
    try {
      const qs = since ? `?since=${encodeURIComponent(since)}` : '';
      const { events: cloudEvents } = await api(`/events${qs}`, {}, token);

      setEvents(prev => {
        // 全量+增量统一用合并：本地新数据不会被云端的旧数据覆盖
        const map = new Map(prev.map(e => [e.id, e]));
        for (const ce of cloudEvents) {
          const local = map.get(ce.id);
          if (!local || ce.updated_at > local.updatedAt) {
            map.set(ce.id, {
              id: ce.id, title: ce.title, date: ce.date, time: ce.time || '',
              endTime: ce.end_time || '', location: ce.location || '', people: ce.people || '',
              raw: ce.raw || '', type: (ce.type || 'event') as 'event' | 'task',
              completed: !!ce.completed, updatedAt: ce.updated_at,
              dateConfirmed: (ce.date_confirmed ?? 1) as 0 | 1,
            });
          }
        }
        return Array.from(map.values());
      });
      localStorage.setItem('schedule_last_sync', String(Date.now()));
      setOffline(false);
      return true;
    } catch {
      // 拉不到就是离线待同步。顶栏那个点的意义是「我记的东西不会丢」，
      // 所以离线必须让人看得见，不能继续静默失败。
      setOffline(true);
      return false;
    }
    finally { setIsSyncing(false); }
  };

  const pushToCloud = async (event: ScheduleEvent, method: 'POST' | 'PUT' | 'DELETE') => {
    if (!token) return;
    try {
      if (method === 'DELETE') {
        await api(`/events/${event.id}`, { method: 'DELETE' }, token);
      } else if (method === 'PUT') {
        await api(`/events/${event.id}`, { method: 'PUT', body: JSON.stringify({ title: event.title, date: event.date, time: event.time, endTime: event.endTime, location: event.location, people: event.people, raw: event.raw, updatedAt: event.updatedAt, type: event.type, completed: event.completed, dateConfirmed: event.dateConfirmed ?? 1 }) }, token);
      } else {
        await api('/events', { method: 'POST', body: JSON.stringify(event) }, token);
      }
    } catch { /* 静默失败，下次同步修复 */ }
  };

  // ==================== 认证操作 ====================

  const handleSendCode = async () => {
    if (!activateEmail || activateLoading) return;
    setActivateLoading(true); setActivateError('');
    try {
      const data = await api('/auth/send-code', { method: 'POST', body: JSON.stringify({ email: activateEmail }) });
      if (!data.code_sent) {
        // 邮件没送达：后端不会回传验证码，这里也不自动填码，
        // 留在邮箱步骤让用户重试，不给任何旁路。
        setActivateError(data.error || '验证码发送失败，请稍后重试');
        return;
      }
      setActivateStep('code');
    } catch (e: unknown) {
      setActivateError((e as Error).message);
    } finally { setActivateLoading(false); }
  };

  const handleVerifyCode = async () => {
    if (!activateCode || activateLoading) return;
    setActivateLoading(true); setActivateError('');
    try {
      const data = await api('/auth/verify', { method: 'POST', body: JSON.stringify({ email: activateEmail, code: activateCode }) });
      localStorage.setItem('schedule_token', data.token);
      setToken(data.token);
      setUser(data.user);
      setShowActivate(false);
      setActivateEmail(''); setActivateCode(''); setActivateStep('email');
      setActivateSuccess(true);
      setTimeout(() => setActivateSuccess(false), 3000);
    } catch (e: unknown) {
      setActivateError((e as Error).message);
    } finally { setActivateLoading(false); }
  };

  const handleLogout = () => {
    localStorage.removeItem('schedule_token');
    localStorage.removeItem('schedule_last_sync');
    setToken(null); setUser(null);
  };



  const [icalUrl, setIcalUrl] = useState('');

  const handleShowCalModal = async () => {
    setShowCalModal(true);
    if (!token) return;
    try {
      const data = await api('/auth/cal-token', {}, token);
      setIcalUrl(`webcal://schedule-api.boluomate.com/events/ical?token=${encodeURIComponent(data.cal_token)}`);
    } catch { /* ignore */ }
  };

  const copyIcalUrl = async () => {
    if (!icalUrl) return;
    try {
      await navigator.clipboard.writeText(icalUrl);
      setIcalCopied(true);
      setTimeout(() => setIcalCopied(false), 2500);
    } catch { /* fallback */ }
  };

  // ==================== 一句话就记 ====================

  // 解析结果 → 一条记录。规则解不出日期时落今天并标待确认，
  // 原话完整保留，用户扫一眼改掉即可（必须可修正，而非必须成功）。
  const handleParsed = (parsed: ParsedResult) => {
    const ev: ScheduleEvent = {
      id: crypto.randomUUID(),
      title: parsed.title || parsed.raw,
      date: parsed.date,
      time: parsed.time,
      endTime: '',
      location: '',
      people: '',
      raw: parsed.raw,
      updatedAt: Date.now(),
      type: parsed.time ? 'event' : 'task',
      completed: false,
      dateConfirmed: parsed.dateConfirmed,
    };
    setEvents(prev => [...prev, ev]);
    if (isOnline && token) pushToCloud(ev, 'POST');
    setDetailDate(parsed.date);
  };

  // ==================== 日程操作 ====================

  const startEdit = (event: ScheduleEvent) => {
    setEditingEventId(event.id);
    setEditForm({ title: event.title, date: event.date, time: event.time, endTime: event.endTime, location: event.location, people: event.people });
  };

  const saveEdit = async () => {
    if (!editingEventId) return;
    const existing = events.find(e => e.id === editingEventId);
    const updated: ScheduleEvent = {
      id: editingEventId,
      title: editForm.title,
      date: editForm.date,
      time: editForm.time,
      endTime: editForm.endTime,
      location: editForm.location,
      people: editForm.people,
      raw: existing?.raw || '',
      updatedAt: Date.now(),
      type: existing?.type || 'event',
      completed: existing?.completed || false,
      // 用户手动改过日期就算确认了，「待确认」标记该消失
      dateConfirmed: editForm.date !== existing?.date ? 1 : (existing?.dateConfirmed ?? 1),
    };

    if (isOnline && token) await pushToCloud(updated, 'PUT');
    setEvents(prev => prev.map(e => e.id === editingEventId ? updated : e));

    setEditingEventId(null);
    if (detailDate !== editForm.date) setDetailDate(editForm.date);
  };

  const deleteEvent = async (id: string) => {
    if (!confirm('确定要删除这个日程吗？')) return;
    const ev = events.find(e => e.id === id);
    if (isOnline && token && ev) await pushToCloud(ev, 'DELETE');
    setEvents(prev => prev.filter(e => e.id !== id));
  };

  const toggleTaskCompleted = async (id: string) => {
    setEvents(prev => prev.map(e => e.id === id ? { ...e, completed: !e.completed, updatedAt: Date.now() } : e));
    if (isOnline && token) {
      try { await api(`/events/${id}/toggle`, { method: 'PUT' }, token); } catch { /* ignore */ }
    }
  };

  const handleExport = () => {
    const sorted = [...events].sort((a, b) => a.date.localeCompare(b.date));
    const rows = sorted.map(e => [e.date, e.time, e.endTime, e.title, e.location, e.people, e.raw]);
    const csv = ['﻿日期,开始时间,结束时间,事项,地点,人员,备注', ...rows.map(r => r.map(c => `"${c}"`).join(','))].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = `日程表_${formatLocalDate(new Date())}.csv`; a.click();
  };

  const generateCsvTemplate = () => {
    const sample = [
      '日期,开始时间,结束时间,事项,地点,人员,备注',
      '2026-07-20,08:50,10:30,初始训练-模拟航班,青浦B777经济静态舱,张教员',
      '2026-07-21,12:50,13:50,团队周会,C楼201,全组',
      '2026-07-22,,,整理文档,,,培训材料归档',
    ].join('\n');
    const blob = new Blob(['﻿' + sample], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = 'schedule_template.csv'; a.click();
  };

  const parseImportFile = async (file: File) => {
    try {
      const ext = file.name.split('.').pop()?.toLowerCase();

      if (file.size > MAX_IMPORT_FILE_BYTES) {
        alert(`文件太大（${(file.size / 1024 / 1024).toFixed(1)}MB），请拆分后再导入`);
        return;
      }

      if (ext === 'csv') {
        setImportText(await file.text());
      } else if (ext === 'xlsx' || ext === 'xlsm') {
        // 动态引入：解析库只在真的要导入时才下载，不占首屏。
        // universal 版不走 Web Worker，避免打包时的 worker chunk 问题。
        const { readSheet } = await import('read-excel-file/universal');
        const rows = (await readSheet(file)) as unknown[][];

        // 智能检测表头映射到模板格式：日期,开始时间,结束时间,事项,地点,人员,备注
        let header: string[] | null = null;
        let dataRows = rows;
        if (rows[0] && rows[0].some(c => String(c).includes('日期') || String(c).includes('时间') || String(c).includes('事项') || String(c).includes('内容'))) {
          header = rows[0].map(c => cellToText(c));
          dataRows = rows.slice(1);
        }

        const findCol = (ks: string[]) => {
          if (!header) return -1;
          return header.findIndex(c => ks.some(k => c.includes(k)));
        };
        const idxD = findCol(['日期']);
        const idxT = findCol(['开始时间', '时间']);
        const idxE = findCol(['结束时间']);
        const idxC = findCol(['内容', '事项', '日程', '标题']);
        const idxL = findCol(['地点', '位置']);
        const idxP = findCol(['人员', '参与人']);
        const idxN = findCol(['备注', '描述', '说明']);

        const csvLines = ['日期,开始时间,结束时间,事项,地点,人员,备注'];
        for (const r of dataRows) {
          const s = r.map(c => cellToText(c).trim());
          if (s.every(c => !c)) continue;
          const date = idxD >= 0 ? s[idxD] : s[0] || '';
          const time = idxT >= 0 ? s[idxT] : s[1] || '';
          const endTime = idxE >= 0 ? s[idxE] : s[2] || '';
          const content = idxC >= 0 ? s[idxC] : s[3] || '';
          const location = idxL >= 0 ? s[idxL] : s[4] || '';
          const people = idxP >= 0 ? s[idxP] : s[5] || '';
          const note = idxN >= 0 ? s[idxN] : s[6] || '';
          if (!date && !content) continue;
          csvLines.push([date, time, endTime, content, location, people, note].map(c => c.includes(',') ? `"${c}"` : c).join(','));
        }
        setImportText(csvLines.join('\n'));
      } else {
        // PDF / docx / txt / ics / json 等→ 读为文本，交给 AI 解析
        setImportText(await file.text());
      }
    } catch { alert('文件读取失败'); }
  };

  const parseImportText = () => {
    const lines = importText.replace(/^﻿/, '').split('\n').map(l => l.trim()).filter(Boolean);
    // 跳过表头
    const startIdx = lines[0]?.startsWith('日期') ? 1 : 0;
    const preview: ScheduleEvent[] = [];

    for (let i = startIdx; i < lines.length; i++) {
      const cells = parseCsvLine(lines[i]);
      const colDate = cells[0] || '', colTime = cells[1] || '', colEndTime = cells[2] || '', colTitle = cells[3] || '', colLocation = cells[4] || '', colPeople = cells[5] || '', colNote = cells[6] || '';
      const title = colTitle || '未命名';

      const smartDate = parseSmartDate(colNote || colTitle);
      const timeObj = extractTime(colNote || colTitle);
      const isTask = !colTime && !smartDate && !timeObj.matched;

      let date = colDate;
      if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
        date = smartDate ? formatLocalDate(smartDate) : formatLocalDate(new Date());
      }
      let time = colTime;
      if (!/^\d{2}:\d{2}$/.test(time)) {
        time = timeObj.matched ? timeObj.str : (isTask ? '' : '09:00');
      }

      preview.push({
        id: crypto.randomUUID(), title, date, time,
        endTime: colEndTime, location: colLocation, people: colPeople, raw: colNote || colTitle, updatedAt: Date.now(),
        type: isTask ? 'task' : 'event', completed: false,
      });
    }

    if (preview.length === 0) { alert('未识别到有效数据'); return; }
    setImportPreview(preview);
  };

  const confirmImport = () => {
    if (!importPreview) return;
    setEvents(prev => {
      const existing = new Set(prev.map(e => `${e.date}|${e.time}|${e.title}`));
      const deduped = importPreview.filter(e => !existing.has(`${e.date}|${e.time}|${e.title}`));
      const added = [...prev, ...deduped];
      if (isOnline && token) deduped.forEach(e => pushToCloud(e, 'POST'));
      // 保存导入历史
      const group = { id: crypto.randomUUID(), name: `导入 ${new Date().toLocaleDateString('zh-CN')}`, count: deduped.length, time: new Date().toISOString() };
      const groups = [group, ...importGroups].slice(0, 20);
      setImportGroups(groups);
      localStorage.setItem('schedule_import_groups', JSON.stringify(groups));
      return added;
    });
    setImportPreview(null);
    setShowImportModal(false);
  };

  const deleteImportGroup = (id: string) => {
    const groups = importGroups.filter(g => g.id !== id);
    setImportGroups(groups);
    localStorage.setItem('schedule_import_groups', JSON.stringify(groups));
  };

  // ==================== 日历渲染 ====================

  const dayEvents = (detailDate && isOnline)
    ? events.filter(e => e.date === detailDate && e.type !== 'task').sort((a, b) => a.time.localeCompare(b.time))
    : [];
  const dayTasks = (detailDate && isOnline)
    ? events.filter(e => e.date === detailDate && e.type === 'task')
        .sort((a, b) => (a.completed ? 1 : 0) - (b.completed ? 1 : 0) || b.updatedAt - a.updatedAt)
    : [];


  // ==================== UI ====================

  return (
    <main className="min-h-screen pb-16 flex flex-col bg-[#F7F5F2]/90">
      {/* 内容区实底：背景图只在最外圈露出，内容区不透明 ——
          隐私视觉要的是「隔着一层看不清楚」，不是「看得出背后有张图」 */}
      {/* v1.0 更新弹窗 */}
      {showVersionModal && (
        <div className="fixed inset-0 z-[70] flex items-center justify-center bg-black/50 backdrop-blur-sm p-4" onClick={dismissVersionModal}>
          <div className="bg-white rounded-2xl w-full max-w-xs p-6 shadow-lg animate-slide-up" onClick={e => e.stopPropagation()}>
            <div className="flex items-center gap-2.5 mb-5">
              <img src="/icon-192x192.png" alt="" className="w-8 h-8 rounded-lg" />
              <div>
                <h2 className="text-lg font-bold text-[#1C1C1C] leading-tight">菠萝日程</h2>
                <span className="text-xs font-semibold text-[#ED6A3B]">v4.0</span>
              </div>
            </div>

            <div className="space-y-3 mb-6 text-xs text-[#5C5C5C]">
              <div className="flex gap-2.5"><span className="text-sm shrink-0">说话就记</span><span className="text-[#A0A0A0]">点麦克风说一句，它自己变成日程</span></div>
              <div className="flex gap-2.5"><span className="text-sm shrink-0">一周一屏</span><span className="text-[#A0A0A0]">上面是这周的安排，下面是这周做了什么</span></div>
              <div className="flex gap-2.5"><span className="text-sm shrink-0">文件导入</span><span className="text-[#A0A0A0]">📎 上传课表 CSV/Excel · 预览后确认</span></div>
              <div className="flex gap-2.5"><span className="text-sm shrink-0">多设备同步</span><span className="text-[#A0A0A0]">邮箱激活 · 顶栏常驻同步状态</span></div>
              <div className="flex gap-2.5"><span className="text-sm shrink-0">苹果日历</span><span className="text-[#A0A0A0]">扫码订阅 · 15 分钟自动刷新</span></div>
              <div className="flex gap-2.5"><span className="text-sm shrink-0">你的数据</span><span className="text-[#A0A0A0]">各自独立，互不可见</span></div>
            </div>

            <button onClick={dismissVersionModal}
              className="w-full h-11 bg-[#1C1C1C] text-white rounded-xl text-sm font-semibold hover:bg-[#333] transition-colors">
              开始使用
            </button>
          </div>
        </div>
      )}

      {/* Header */}
      <header className="bg-white px-5 py-4 sm:py-5 sticky top-0 z-50 border-b border-[#E8E4DF]">
        <div className="flex flex-wrap justify-between items-center gap-y-2 max-w-full mx-auto">
          <h1 className="text-xl font-semibold text-[#1C1C1C] flex items-center gap-2 tracking-tight shrink-0">
            <img src="/icon-192x192.png" alt="" className="w-7 h-7 rounded" /> 菠萝日程
          </h1>
          <div className="flex items-center gap-1 flex-wrap">
            <div className="relative group">
              <span className={`w-2.5 h-2.5 rounded-full block cursor-default ${isOnline ? 'bg-[#059669] shadow-[0_0_6px_rgba(5,150,105,0.4)]' : 'bg-[#D9D4CF]'}`} />
              <div className="absolute right-0 top-6 hidden group-hover:block bg-[#1C1C1C] text-white text-xs rounded-lg px-3 py-2 whitespace-nowrap z-[60] shadow-lg">
                {isOnline ? (
                  <><span className="text-[#34d399]">●</span> {user?.email}<br /><span className="text-[#A0A0A0]">已激活 · 多设备自动同步</span></>
                ) : (
                  '未登录，点击右侧激活'
                )}
              </div>
            </div>
            {isOnline && (
              <button onClick={() => syncFromCloud()} disabled={isSyncing}
                className="w-9 h-9 rounded-lg hover:bg-[#F3F1ED] transition-colors flex items-center justify-center" aria-label="同步" title="同步">
                <RefreshCw className={`w-4 h-4 text-[#A0A0A0] ${isSyncing ? 'animate-spin' : ''}`} />
              </button>
            )}
            {isOnline ? (
              <button onClick={handleLogout}
                className="w-9 h-9 rounded-lg hover:bg-[#FEE2E2] transition-colors flex items-center justify-center" aria-label="退出" title="退出登录">
                <LogOut className="w-4 h-4 text-[#A0A0A0]" />
              </button>
            ) : (
              <button onClick={() => setShowActivate(true)}
                className="h-9 px-4 bg-[#1C1C1C] text-white text-sm font-semibold rounded-lg hover:bg-[#333] transition-colors flex items-center gap-1.5" title="激活同步">
                <Mail className="w-3.5 h-3.5" /> 激活
              </button>
            )}
            {isOnline && (
              <button onClick={handleShowCalModal}
                className="w-9 h-9 rounded-lg hover:bg-[#F3F1ED] transition-colors flex items-center justify-center" aria-label="日历订阅" title="导出到手机日历">
                <svg className="w-4 h-4 text-[#A0A0A0]" fill="none" stroke="currentColor" viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="18" rx="2" strokeWidth={2} /><path d="M16 2v4M8 2v4M3 10h18" strokeWidth={2} /></svg>
              </button>
            )}
            <button onClick={handleExport}
              className="w-9 h-9 rounded-lg hover:bg-[#F3F1ED] transition-colors flex items-center justify-center" aria-label="导出" title="导出CSV">
              <Download className="w-4 h-4 text-[#A0A0A0]" />
            </button>
            <button onClick={() => { setImportText(''); setImportPreview(null); setShowImportModal(true); }}
              className="w-9 h-9 rounded-lg hover:bg-[#F3F1ED] transition-colors flex items-center justify-center" aria-label="导入" title="导入CSV/Excel">
              <Upload className="w-4 h-4 text-[#A0A0A0]" />
            </button>
            <button onClick={generateCsvTemplate}
              className="w-9 h-9 rounded-lg hover:bg-[#F3F1ED] transition-colors flex items-center justify-center" aria-label="模板下载" title="CSV模板下载">
              <svg className="w-4 h-4 text-[#A0A0A0]" fill="none" stroke="currentColor" viewBox="0 0 24 24"><rect x="3" y="5" width="18" height="16" rx="1" strokeWidth={2}/><path d="M3 5h18M8 5v16M3 10h18" strokeWidth={2}/></svg>
            </button>
            {/* v4.0：AI 设置面板已删除 —— 用户不该为系统内部机制操心 */}
            <button onClick={() => setShowFeedback(true)}
              className="w-9 h-9 rounded-lg hover:bg-[#F3F1ED] transition-colors flex items-center justify-center" aria-label="反馈" title="反馈建议">
              <svg className="w-4 h-4 text-[#A0A0A0]" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-4l-4 4z" /></svg>
            </button>
            <button onClick={() => setShowHelp(true)}
              className="w-9 h-9 rounded-lg hover:bg-[#F3F1ED] transition-colors flex items-center justify-center" aria-label="帮助" title="使用说明">
              <svg className="w-4 h-4 text-[#A0A0A0]" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
            </button>
          </div>
        </div>
      </header>

      {/* 激活弹窗 */}
      {showActivate && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/30" onClick={() => { if (!activateLoading) { setShowActivate(false); setActivateStep('email'); setActivateError(''); } }}>
          <div className="bg-white rounded-2xl p-6 mx-4 w-full max-w-sm shadow-lg" onClick={e => e.stopPropagation()}>
            <h2 className="text-lg font-semibold text-[#1C1C1C] mb-1">激活跨设备同步</h2>
            <p className="text-sm text-[#A0A0A0] mb-5">
              {activateStep === 'email' ? '输入邮箱，发送验证码激活' : `验证码已发送到 ${activateEmail}`}
            </p>

            {activateStep === 'email' ? (
              <>
                <input type="email" value={activateEmail} onChange={e => setActivateEmail(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && handleSendCode()}
                  placeholder="your@email.com"
                  className="w-full px-4 py-3 border border-[#E8E4DF] rounded-lg text-sm outline-none focus:border-[#1C1C1C] transition-colors mb-3"
                  autoFocus />
                {activateError && <p className="text-red-500 text-xs mb-3">{activateError}</p>}
                <button onClick={handleSendCode} disabled={activateLoading || !activateEmail}
                  className="w-full h-11 bg-[#1C1C1C] text-white rounded-lg text-sm font-semibold hover:bg-[#333] disabled:opacity-40 transition-colors">
                  {activateLoading ? '发送中...' : '发送验证码'}
                </button>
              </>
            ) : (
              <>
                <input type="text" value={activateCode} onChange={e => setActivateCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  onKeyDown={e => e.key === 'Enter' && handleVerifyCode()}
                  placeholder="输入6位验证码" maxLength={6}
                  className="w-full px-4 py-3 border border-[#E8E4DF] rounded-lg text-sm outline-none focus:border-[#1C1C1C] transition-colors mb-3 text-center text-2xl tracking-widest"
                  autoFocus />
                {activateError && <p className="text-red-500 text-xs mb-3">{activateError}</p>}
                <button onClick={handleVerifyCode} disabled={activateLoading || activateCode.length !== 6}
                  className="w-full h-11 bg-[#1C1C1C] text-white rounded-lg text-sm font-semibold hover:bg-[#333] disabled:opacity-40 transition-colors mb-2">
                  {activateLoading ? '验证中...' : '激活'}
                </button>
                <button onClick={() => { setActivateStep('email'); setActivateError(''); }}
                  className="w-full py-2 text-sm text-[#A0A0A0] hover:text-[#5C5C5C] transition-colors">
                  换一个邮箱
                </button>
              </>
            )}

            <button onClick={() => { if (!activateLoading) { setShowActivate(false); setActivateStep('email'); setActivateError(''); } }}
              className="w-full py-2 text-sm text-[#A0A0A0] hover:text-[#5C5C5C] transition-colors mt-1">
              取消
            </button>
          </div>
        </div>
      )}

      {/* 日历订阅弹窗 */}
      {showCalModal && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/30" onClick={() => { setShowCalModal(false); setIcalCopied(false); }}>
          <div className="bg-white rounded-2xl p-6 mx-4 w-full max-w-sm shadow-lg" onClick={e => e.stopPropagation()}>
            <h2 className="text-lg font-semibold text-[#1C1C1C] mb-1">导出到手机日历</h2>
            <p className="text-sm text-[#A0A0A0] mb-5">iPhone 相机扫码自动订阅，或复制链接手动添加</p>

            <div className="flex flex-col items-center mb-4">
              <img
                src={`https://api.qrserver.com/v1/create-qr-code/?size=180x180&data=${encodeURIComponent(icalUrl)}`}
                alt="日历订阅二维码"
                className="w-44 h-44 rounded-lg border border-[#E8E4DF]"
              />
              <p className="text-xs text-[#A0A0A0] mt-2">📷 用 iPhone 相机扫描二维码</p>
            </div>

            <div className="bg-[#F7F5F2] rounded-lg p-3 mb-1 break-all text-xs text-[#5C5C5C] font-mono select-all max-h-20 overflow-y-auto">
              {icalUrl}
            </div>

            <div className="flex gap-2 mt-4">
              <button onClick={copyIcalUrl}
                className="flex-1 h-11 bg-[#1C1C1C] text-white rounded-lg text-sm font-semibold hover:bg-[#333] transition-colors">
                {icalCopied ? '已复制' : '复制链接'}
              </button>
              <button onClick={() => { setShowCalModal(false); setIcalCopied(false); }}
                className="w-11 h-11 rounded-lg border border-[#E8E4DF] text-[#A0A0A0] text-sm font-medium hover:bg-[#F3F1ED] transition-colors flex items-center justify-center">
                ×
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 反馈弹窗 */}
      {showFeedback && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/30" onClick={() => { setShowFeedback(false); setFeedbackSent(false); setFeedbackText(''); }}>
          <div className="bg-white rounded-2xl p-6 mx-4 w-full max-w-sm shadow-lg" onClick={e => e.stopPropagation()}>
            <h2 className="text-lg font-semibold text-[#1C1C1C] mb-1">反馈建议</h2>
            <p className="text-sm text-[#A0A0A0] mb-4">遇到问题或有改进建议？告诉我们</p>
            {feedbackSent ? (
              <p className="text-[#059669] text-sm text-center py-4">已收到，感谢反馈！</p>
            ) : (
              <>
                <textarea value={feedbackText} onChange={e => setFeedbackText(e.target.value)}
                  placeholder="请告诉我们你的想法..."
                  rows={4} maxLength={500}
                  className="w-full px-4 py-3 border border-[#E8E4DF] rounded-lg text-sm outline-none focus:border-[#1C1C1C] transition-colors mb-4 resize-none" />
                <div className="flex gap-2">
                  <button onClick={submitFeedback} disabled={!feedbackText.trim()}
                    className="flex-1 h-11 bg-[#1C1C1C] text-white rounded-lg text-sm font-semibold hover:bg-[#333] disabled:opacity-40 transition-colors">
                    提交反馈
                  </button>
                  <button onClick={() => { setShowFeedback(false); setFeedbackSent(false); setFeedbackText(''); }}
                    className="w-11 h-11 rounded-lg border border-[#E8E4DF] text-[#A0A0A0] text-sm font-medium hover:bg-[#F3F1ED] transition-colors flex items-center justify-center">
                    ×
                  </button>
                </div>
              </>
            )}
          </div>
        </div>
      )}

      {/* 使用说明弹窗 */}
      {showHelp && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/40 backdrop-blur-sm" onClick={() => setShowHelp(false)}>
          <div className="bg-white rounded-2xl p-6 mx-4 w-full max-w-sm shadow-lg max-h-[80vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
            <div className="flex justify-between items-center mb-5">
              <h2 className="text-lg font-semibold text-[#1C1C1C]">使用说明 <span className="text-[10px] font-normal text-[#C0BDB8]">v1.0</span></h2>
              <button onClick={() => setShowHelp(false)} className="w-8 h-8 rounded-lg hover:bg-[#F3F1ED] text-[#A0A0A0] flex items-center justify-center transition-colors">&times;</button>
            </div>

            <div className="space-y-5">
              <div>
                <h3 className="text-sm font-semibold text-[#1C1C1C] mb-1.5">快速记录</h3>
                <p className="text-sm text-[#5C5C5C] leading-relaxed">直接输入自然语言，如「<span className="text-[#ED6A3B]">后天下午3点买菜</span>」「<span className="text-[#ED6A3B]">上周五组会</span>」，回车即保存。日期、时间自动识别。<br /><span className="text-xs text-[#A0A0A0]">认不出来时会标一个「待确认」，点一下改掉就行</span></p>
              </div>

              <div>
                <h3 className="text-sm font-semibold text-[#1C1C1C] mb-1.5">添加到桌面</h3>
                <p className="text-sm text-[#5C5C5C] leading-relaxed">iPhone Safari 点分享按钮 → 添加到主屏幕<br />Android Chrome 点菜单 → 添加到主屏幕<br /><span className="text-xs text-[#A0A0A0]">添加后像 App 一样打开，体验更流畅</span></p>
              </div>

              <div>
                <h3 className="text-sm font-semibold text-[#1C1C1C] mb-1.5">语音输入</h3>
                <p className="text-sm text-[#5C5C5C] leading-relaxed">点一下麦克风开始说，再点一下结束。说完直接落库，不用二次确认。一口气说两件事，会自动记成两条。<br /><span className="text-xs text-[#A0A0A0]">微信里、Firefox 里都能用 —— 走的是服务端转写，不依赖浏览器</span></p>
              </div>

              <div>
                <h3 className="text-sm font-semibold text-[#1C1C1C] mb-1.5">多设备同步</h3>
                <p className="text-sm text-[#5C5C5C] leading-relaxed">点击右上角「激活」→ 输入邮箱 → 收到验证码 → 填入 → 完成。之后所有设备自动同步，无需再次登录。</p>
              </div>

              <div>
                <h3 className="text-sm font-semibold text-[#1C1C1C] mb-1.5">苹果日历订阅</h3>
                <p className="text-sm text-[#5C5C5C] leading-relaxed">激活后点日历图标 → iPhone 相机扫码 → 自动订阅。日程实时出现在系统日历里，支持小组件和通知。</p>
              </div>

              <div>
                <h3 className="text-sm font-semibold text-[#1C1C1C] mb-1.5">导出</h3>
                <p className="text-sm text-[#5C5C5C] leading-relaxed">点下载按钮导出 CSV 文件，可用 Excel 或 Numbers 打开。</p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 导入弹窗（两步模式） */}
      {showImportModal && (
        <div className="fixed inset-0 z-[65] flex items-center justify-center bg-black/40 backdrop-blur-sm p-4" onClick={() => { setShowImportModal(false); setImportPreview(null); }}>
          <div className="bg-white rounded-2xl w-full max-w-lg max-h-[85vh] flex flex-col shadow-lg" onClick={e => e.stopPropagation()}>
            {importPreview ? (
              /* 第二步：解析预览 */
              <>
                <div className="flex justify-between items-center p-5 border-b border-[#E8E4DF] shrink-0">
                  <h2 className="font-semibold text-[#1C1C1C]">解析预览 · {importPreview.length} 条</h2>
                  <button onClick={() => setImportPreview(null)} className="w-8 h-8 rounded-lg hover:bg-[#F3F1ED] text-[#A0A0A0] flex items-center justify-center">&times;</button>
                </div>
                <div className="overflow-y-auto p-5 space-y-3 flex-1">
                  {importPreview.map((e, i) => (
                    <div key={e.id} className="p-3 bg-[#F7F5F2] rounded-xl border border-[#E8E4DF] space-y-2">
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-[#A0A0A0] w-5 shrink-0">{i + 1}</span>
                        <input value={e.title} onChange={ev => {
                          const next = [...importPreview]; next[i] = { ...next[i], title: ev.target.value }; setImportPreview(next);
                        }} className="flex-1 px-2 py-1 border border-[#E8E4DF] rounded text-sm bg-white outline-none focus:border-[#1C1C1C]" />
                        <button onClick={() => setImportPreview(prev => prev!.filter((_, j) => j !== i))}
                          className="text-[#A0A0A0] hover:text-red-500 px-1">&times;</button>
                      </div>
                      <div className="flex gap-2 items-center">
                        <input type="date" value={e.date} onChange={ev => {
                          const next = [...importPreview]; next[i] = { ...next[i], date: ev.target.value }; setImportPreview(next);
                        }} className="px-2 py-1 border border-[#E8E4DF] rounded text-xs bg-white outline-none focus:border-[#1C1C1C]" />
                        <input type="time" value={e.time} onChange={ev => {
                          const next = [...importPreview]; next[i] = { ...next[i], time: ev.target.value }; setImportPreview(next);
                        }} className="px-2 py-1 border border-[#E8E4DF] rounded text-xs bg-white outline-none focus:border-[#1C1C1C] w-24" />
                        {/* v4.0：类型由系统按有无时间判断，不让用户选 */}
                        <span className="text-xs text-[#A0A0A0] truncate flex-1">{e.raw}</span>
                      </div>
                    </div>
                  ))}
                </div>
                <div className="flex gap-2 p-5 border-t border-[#E8E4DF] shrink-0">
                  <button onClick={() => setImportPreview(null)}
                    className="flex-1 h-11 rounded-lg border border-[#E8E4DF] text-sm text-[#5C5C5C] hover:bg-[#F3F1ED] transition-colors">返回修改</button>
                  <button onClick={confirmImport}
                    className="flex-1 h-11 bg-[#ED6A3B] text-white rounded-lg text-sm font-semibold hover:bg-[#D45D2E] transition-colors">确认导入 {importPreview.length} 条</button>
                </div>
              </>
            ) : (
              /* 第一步：输入原文 */
              <>
                <div className="flex justify-between items-center p-5 border-b border-[#E8E4DF] shrink-0">
                  <h2 className="font-semibold text-[#1C1C1C]">导入日程</h2>
                  <button onClick={() => setShowImportModal(false)} className="w-8 h-8 rounded-lg hover:bg-[#F3F1ED] text-[#A0A0A0] flex items-center justify-center">&times;</button>
                </div>
                <div className="p-5 space-y-4 flex-1 flex flex-col min-h-0">
                  <p className="text-xs text-[#A0A0A0]">每行一条，格式：日期,开始时间,结束时间,事项,地点,人员,备注（无时间的自动归为任务）</p>
                  <textarea value={importText} onChange={e => setImportText(e.target.value)}
                    placeholder={`2026-07-20,08:50,初始训练-模拟航班,青浦B777经济静态舱\n2026-07-21,12:50,团队周会,C楼201\n2026-07-22,,整理文档`}
                    className="flex-1 w-full p-3 border border-[#E8E4DF] rounded-lg text-sm outline-none focus:border-[#1C1C1C] resize-none font-mono" />
                  <div className="flex gap-2">
                    <label className="flex-1 h-11 rounded-lg border border-dashed border-[#D9D4CF] text-sm text-[#5C5C5C] hover:bg-[#F3F1ED] transition-colors flex items-center justify-center gap-1.5 cursor-pointer">
                      <Upload className="w-4 h-4" /> 上传 CSV / XLSX
                      <input type="file" accept=".csv,.xlsx" onChange={e => { if (e.target.files?.[0]) parseImportFile(e.target.files[0]); e.target.value = ''; }} className="hidden" />
                    </label>
                  </div>
                  <button onClick={parseImportText} disabled={!importText.trim()}
                    className="w-full h-11 bg-[#ED6A3B] text-white rounded-lg text-sm font-semibold hover:bg-[#D45D2E] disabled:opacity-40 transition-colors">解析预览</button>

                  {/* 导入历史 */}
                  {importGroups.length > 0 && (
                    <div className="border-t border-[#E8E4DF] pt-3">
                      <p className="text-xs text-[#A0A0A0] mb-2">导入历史</p>
                      <div className="space-y-1 max-h-32 overflow-y-auto">
                        {importGroups.map(g => (
                          <div key={g.id} className="flex items-center justify-between text-xs text-[#5C5C5C] py-1">
                            <span>{g.name} · {g.count} 条</span>
                            <button onClick={() => deleteImportGroup(g.id)} className="text-[#A0A0A0] hover:text-red-500">&times;</button>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </>
            )}
          </div>
        </div>
      )}

      {/* 激活成功提示 */}
      {activateSuccess && (
        <div className="fixed top-20 left-1/2 -translate-x-1/2 z-[60] bg-[#1C1C1C] text-white px-5 py-3 rounded-xl shadow-lg text-sm font-medium animate-bounce">
          激活成功！数据自动同步中
        </div>
      )}

      {/* 内容区：日程 + 日历并排 */}
      <div className="flex-1 flex flex-col md:flex-row gap-3 mx-3 mt-3 overflow-hidden min-h-0">

      {/* Detail Card */}
      {detailDate && (
        <div className="md:w-1/4 bg-white rounded-2xl p-4 shadow-sm border border-[#E8E4DF] overflow-y-auto">
          <div className="flex justify-between items-center mb-4">
            <h2 className="font-semibold text-[#1C1C1C]">{detailDate} 日程</h2>
            <button onClick={() => setDetailDate(null)}
              className="w-8 h-8 bg-[#F3F1ED] hover:bg-[#E8E4DF] rounded-lg text-[#A0A0A0] flex items-center justify-center transition-colors" aria-label="关闭">
              ×
            </button>
          </div>
          {dayEvents.length === 0 && dayTasks.length === 0 ? (
            <p className="text-[#A0A0A0] text-center py-8 text-sm">
              {isOnline ? '暂无日程，在下方输入' : '点击右上角激活同步后可查看日程'}
            </p>
          ) : (
            <div className="space-y-4">
              {/* 定时日程 */}
              {dayEvents.length > 0 && (
                <div className="space-y-2">
                  {dayEvents.map(e => (
                    <div key={e.id} className="p-3 bg-[#F7F5F2] rounded-xl border border-[#E8E4DF]">
                      {editingEventId === e.id ? (
                        <div className="space-y-3">
                          <div>
                            <label className="text-xs text-[#A0A0A0] mb-1 block">事项</label>
                            <input type="text" value={editForm.title} onChange={ev => setEditForm({ ...editForm, title: ev.target.value })}
                              className="w-full px-3 py-2 border border-[#E8E4DF] rounded-lg text-sm outline-none focus:border-[#1C1C1C]" />
                            {/* 原话：只在编辑时展开，平时不占地方 */}
                            {events.find(e => e.id === editingEventId)?.raw && (
                              <p className="text-xs text-[#A0A0A0] mt-1.5 leading-relaxed">
                                原话：{events.find(e => e.id === editingEventId)?.raw}
                              </p>
                            )}
                            {/* 原话：只在编辑时展开，平时不占地方 */}
                            {events.find(e => e.id === editingEventId)?.raw && (
                              <p className="text-xs text-[#A0A0A0] mt-1.5 leading-relaxed">
                                原话：{events.find(e => e.id === editingEventId)?.raw}
                              </p>
                            )}
                            {/* 原话：只在编辑时展开，平时不占地方 */}
                            {events.find(e => e.id === editingEventId)?.raw && (
                              <p className="text-xs text-[#A0A0A0] mt-1.5 leading-relaxed">
                                原话：{events.find(e => e.id === editingEventId)?.raw}
                              </p>
                            )}
                          </div>
                          <div>
                            <label className="text-xs text-[#A0A0A0] mb-1 block">日期</label>
                            <input type="date" title="日期" value={editForm.date} onChange={ev => setEditForm({ ...editForm, date: ev.target.value })}
                              className="w-full px-3 py-2 border border-[#E8E4DF] rounded-lg text-sm outline-none focus:border-[#1C1C1C]" />
                          </div>
                          <div className="flex gap-3">
                            <div className="flex-1">
                              <label className="text-xs text-[#A0A0A0] mb-1 block">开始时间</label>
                              <input type="time" title="开始时间" value={editForm.time} onChange={ev => setEditForm({ ...editForm, time: ev.target.value })}
                                className="w-full px-3 py-2 border border-[#E8E4DF] rounded-lg text-sm outline-none focus:border-[#1C1C1C]" />
                            </div>
                            <div className="flex-1">
                              <label className="text-xs text-[#A0A0A0] mb-1 block">结束时间</label>
                              <input type="time" title="结束时间" value={editForm.endTime} onChange={ev => setEditForm({ ...editForm, endTime: ev.target.value })}
                                className="w-full px-3 py-2 border border-[#E8E4DF] rounded-lg text-sm outline-none focus:border-[#1C1C1C]" />
                            </div>
                          </div>
                          <div className="flex gap-3">
                            <div className="flex-1">
                              <label className="text-xs text-[#A0A0A0] mb-1 block">地点</label>
                              <input type="text" value={editForm.location} onChange={ev => setEditForm({ ...editForm, location: ev.target.value })}
                                className="w-full px-3 py-2 border border-[#E8E4DF] rounded-lg text-sm outline-none focus:border-[#1C1C1C]" placeholder="教室/会议室" />
                            </div>
                            <div className="flex-1">
                              <label className="text-xs text-[#A0A0A0] mb-1 block">人员</label>
                              <input type="text" value={editForm.people} onChange={ev => setEditForm({ ...editForm, people: ev.target.value })}
                                className="w-full px-3 py-2 border border-[#E8E4DF] rounded-lg text-sm outline-none focus:border-[#1C1C1C]" placeholder="老师/同学" />
                            </div>
                          </div>
                          <div className="flex gap-2 justify-end">
                            <button onClick={() => { setEditingEventId(null); setEditForm({ title: '', date: '', time: '', endTime: '', location: '', people: '' }); }}
                              className="px-4 py-1.5 text-sm text-[#5C5C5C] bg-[#E8E4DF] rounded-lg hover:bg-[#D9D4CF] transition-colors">取消</button>
                            <button onClick={saveEdit} className="px-4 py-1.5 text-sm text-white bg-[#ED6A3B] rounded-lg hover:bg-[#D45D2E] transition-colors">保存</button>
                          </div>
                        </div>
                      ) : (
                        <div className="flex items-center gap-3">
                          <span className="bg-[#ED6A3B] text-white text-sm px-3 py-1.5 rounded-lg font-mono font-semibold min-w-[60px] text-center">{e.time}{e.endTime ? `-${e.endTime}` : ''}</span>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-1.5">
                              <div className="font-medium text-[#1C1C1C] truncate">{e.title}</div>
                              {e.dateConfirmed === 0 && (
                                <button onClick={() => startEdit(e)}
                                  className="shrink-0 text-[10px] text-[#ED6A3B] bg-[#FFF5F0] hover:bg-[#FFE8DC] rounded px-1.5 py-0.5 transition-colors"
                                  title="日期没认出来，改一下">
                                  待确认
                                </button>
                              )}
                            </div>
                            {(e.location || e.people) && <div className="text-xs text-[#A0A0A0] mt-0.5 truncate">{e.location}{e.location && e.people ? ' · ' : ''}{e.people}</div>}
                          </div>
                          <div className="flex gap-1">
                            <button onClick={() => startEdit(e)} className="p-2 text-[#A0A0A0] hover:text-[#ED6A3B] hover:bg-[#FFF5F0] rounded-lg transition-colors" aria-label="编辑">
                              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" /></svg>
                            </button>
                            <button onClick={() => deleteEvent(e.id)} className="p-2 text-[#A0A0A0] hover:text-red-500 hover:bg-red-50 rounded-lg transition-colors" aria-label="删除">
                              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" /></svg>
                            </button>
                          </div>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}

              {/* 分隔线 */}
              {dayEvents.length > 0 && dayTasks.length > 0 && (
                <div className="border-t border-[#E8E4DF]" />
              )}

              {/* 当日任务 */}
              {dayTasks.length > 0 && (
                <div className="space-y-1.5">
                  {dayTasks.map(e => (
                    <div key={e.id} className={`p-3 rounded-xl border border-[#E8E4DF] transition-colors ${e.completed ? 'bg-[#F7F5F2]/50' : 'bg-[#F7F5F2]'}`}>
                      {editingEventId === e.id ? (
                        <div className="space-y-3">
                          <div>
                            <label className="text-xs text-[#A0A0A0] mb-1 block">任务名称</label>
                            <input type="text" value={editForm.title} onChange={ev => setEditForm({ ...editForm, title: ev.target.value })}
                              className="w-full px-3 py-2 border border-[#E8E4DF] rounded-lg text-sm outline-none focus:border-[#1C1C1C]" />
                          </div>
                          <div className="flex gap-3">
                            <div className="flex-1">
                              <label className="text-xs text-[#A0A0A0] mb-1 block">日期</label>
                              <input type="date" title="日期" value={editForm.date} onChange={ev => setEditForm({ ...editForm, date: ev.target.value })}
                                className="w-full px-3 py-2 border border-[#E8E4DF] rounded-lg text-sm outline-none focus:border-[#1C1C1C]" />
                            </div>
                          </div>
                          <div className="flex gap-3">
                            <div className="flex-1">
                              <label className="text-xs text-[#A0A0A0] mb-1 block">地点</label>
                              <input type="text" value={editForm.location} onChange={ev => setEditForm({ ...editForm, location: ev.target.value })}
                                className="w-full px-3 py-2 border border-[#E8E4DF] rounded-lg text-sm outline-none focus:border-[#1C1C1C]" placeholder="教室/会议室" />
                            </div>
                            <div className="flex-1">
                              <label className="text-xs text-[#A0A0A0] mb-1 block">人员</label>
                              <input type="text" value={editForm.people} onChange={ev => setEditForm({ ...editForm, people: ev.target.value })}
                                className="w-full px-3 py-2 border border-[#E8E4DF] rounded-lg text-sm outline-none focus:border-[#1C1C1C]" placeholder="老师/同学" />
                            </div>
                          </div>
                          <div className="flex gap-2 justify-end">
                            <button onClick={() => { setEditingEventId(null); setEditForm({ title: '', date: '', time: '', endTime: '', location: '', people: '' }); }}
                              className="px-4 py-1.5 text-sm text-[#5C5C5C] bg-[#E8E4DF] rounded-lg hover:bg-[#D9D4CF] transition-colors">取消</button>
                            <button onClick={saveEdit} className="px-4 py-1.5 text-sm text-white bg-[#ED6A3B] rounded-lg hover:bg-[#D45D2E] transition-colors">保存</button>
                          </div>
                        </div>
                      ) : (
                        <div className="flex items-center gap-3">
                          <button onClick={() => toggleTaskCompleted(e.id)}
                            className={`w-5 h-5 rounded-full border-2 flex items-center justify-center shrink-0 transition-all ${
                              e.completed
                                ? 'bg-[#ED6A3B] border-[#ED6A3B]'
                                : 'border-[#D9D4CF] hover:border-[#ED6A3B]'
                            }`}>
                            {e.completed && (
                              <svg className="w-3 h-3 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 13l4 4L19 7" />
                              </svg>
                            )}
                          </button>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-1.5">
                              <div className={`font-medium truncate ${e.completed ? 'line-through text-[#A0A0A0]' : 'text-[#1C1C1C]'}`}>{e.title}</div>
                              {e.dateConfirmed === 0 && (
                                <button onClick={() => startEdit(e)}
                                  className="shrink-0 text-[10px] text-[#ED6A3B] bg-[#FFF5F0] hover:bg-[#FFE8DC] rounded px-1.5 py-0.5 transition-colors"
                                  title="日期没认出来，改一下">
                                  待确认
                                </button>
                              )}
                            </div>
                            {(e.location || e.people) && <div className={`text-xs mt-0.5 truncate ${e.completed ? 'line-through text-[#C0BDB8]' : 'text-[#A0A0A0]'}`}>{e.location}{e.location && e.people ? ' · ' : ''}{e.people}</div>}
                          </div>
                          <div className="flex gap-1">
                            <button onClick={() => startEdit(e)} className="p-2 text-[#A0A0A0] hover:text-[#ED6A3B] hover:bg-[#FFF5F0] rounded-lg transition-colors" aria-label="编辑">
                              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" /></svg>
                            </button>
                            <button onClick={() => deleteEvent(e.id)} className="p-2 text-[#A0A0A0] hover:text-red-500 hover:bg-red-50 rounded-lg transition-colors" aria-label="删除">
                              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" /></svg>
                            </button>
                          </div>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* 周视图 —— 一屏两区：上面七天时间轴，下面本周流水 */}
      <div className="flex-1 flex flex-col min-h-0">
        {/* 周切换 */}
        <div className="flex justify-between items-center mb-3 px-1">
          <button onClick={() => setWeekAnchor(d => new Date(d.getFullYear(), d.getMonth(), d.getDate() - 7))}
            className="w-9 h-9 bg-white/70 hover:bg-white rounded-full text-[#5C5C5C] flex items-center justify-center transition-colors" aria-label="上一周">
            <ChevronLeft className="w-5 h-5" />
          </button>
          <div className="text-center">
            <h2 className="text-sm font-semibold text-[#1C1C1C]">
              {weekDates(weekAnchor)[0]} ~ {weekDates(weekAnchor)[6]}
            </h2>
            <button onClick={() => setWeekAnchor(new Date())}
              className="text-xs text-[#ED6A3B] hover:underline">
              回到本周
            </button>
          </div>
          <button onClick={() => setWeekAnchor(d => new Date(d.getFullYear(), d.getMonth(), d.getDate() + 7))}
            className="w-9 h-9 bg-white/70 hover:bg-white rounded-full text-[#5C5C5C] flex items-center justify-center transition-colors" aria-label="下一周">
            <ChevronRight className="w-5 h-5" />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto min-h-0">
          <WeekView
            anchor={weekAnchor}
            events={events.map(e => ({
              id: e.id, title: e.title, date: e.date, time: e.time,
              endTime: e.endTime, location: e.location, people: e.people,
            }))}
            today={new Date()}
            narrowDate={detailDate || weekToDateString(new Date())}
            isNarrow={isNarrow}
            onEventClick={(e) => {
              const full = events.find(x => x.id === e.id);
              if (full) { setDetailDate(full.date); setEditingEventId(full.id); }
            }}
          />
        </div>
      </div>

      </div>

      {/* 输入区 —— 唯一输入入口：麦克风 + 文本框 + 同步状态 */}
      <InputArea
        apiBase={API_BASE}
        token={token}
        onSubmit={handleParsed}
        syncState={isSyncing ? 'syncing' : offline ? 'offline' : 'synced'}
        isNarrow={isNarrow}
      />
    </main>
  );
}
