'use client';

import { useState, useEffect, useRef } from 'react';
import { Send, ChevronLeft, ChevronRight, Download, Upload, LogOut, RefreshCw, Mail, Plus, MessageCircle, X, Mic } from 'lucide-react';
import { read, utils } from 'xlsx';
import { dispatchFileTask } from '../utils/fileDispatcher';
import { adaptPayloadToModel } from '../utils/tokenAdapter';

// ==================== 配置 ====================

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'https://schedule-api.boluomate.com';

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
  raw: string;
  updatedAt: number;
  type: 'event' | 'task';
  completed: boolean;
}

interface User { id: number; email: string; }

// ==================== 主组件 ====================

export default function Home() {
  // 日程状态
  const [events, setEvents] = useState<ScheduleEvent[]>([]);
  const [currentDate, setCurrentDate] = useState(new Date());
  const [selectedDate, setSelectedDate] = useState(new Date());
  const [detailDate, setDetailDate] = useState<string | null>(null);
  const [editingEventId, setEditingEventId] = useState<string | null>(null);
  const [editForm, setEditForm] = useState({ title: '', date: '', time: '' });

  // 对话框状态
  const [showChat, setShowChat] = useState(false);
  const [chatInput, setChatInput] = useState('');
  const [chatMessages, setChatMessages] = useState<{ role: 'user' | 'assistant'; content: string; image?: string; cards?: { date: string; time: string; title: string; type: 'event' | 'task' }[] }[]>([]);
  const [aiConfig, setAiConfig] = useState<{ brand: string; model: string; key: string }>({ brand: 'deepseek', model: 'deepseek-v4-flash', key: '' });
  const [showAiSettings, setShowAiSettings] = useState(false);
  const [chatLoading, setChatLoading] = useState(false);
  const [isRecording, setIsRecording] = useState(false);
  const [showPlusMenu, setShowPlusMenu] = useState(false);
  const recognitionRef = useRef<SpeechRecognition | null>(null);
  const photoInputRef = useRef<HTMLInputElement | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  // 认证状态
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [isSyncing, setIsSyncing] = useState(false);

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

  // v2.0 更新弹窗（首次访问展示一次）
  useEffect(() => {
    const seen = localStorage.getItem('schedule_version_seen');
    if (seen !== 'v2.0') setShowVersionModal(true);
  }, []);

  const dismissVersionModal = () => {
    localStorage.setItem('schedule_version_seen', 'v2.0');
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
    if (!token) return;
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
            map.set(ce.id, { id: ce.id, title: ce.title, date: ce.date, time: ce.time || '', raw: ce.raw || '', type: (ce.type || 'event') as 'event' | 'task', completed: !!ce.completed, updatedAt: ce.updated_at });
          }
        }
        return Array.from(map.values());
      });
      localStorage.setItem('schedule_last_sync', String(Date.now()));
    } catch { /* 静默失败 */ }
    finally { setIsSyncing(false); }
  };

  const pushToCloud = async (event: ScheduleEvent, method: 'POST' | 'PUT' | 'DELETE') => {
    if (!token) return;
    try {
      if (method === 'DELETE') {
        await api(`/events/${event.id}`, { method: 'DELETE' }, token);
      } else if (method === 'PUT') {
        await api(`/events/${event.id}`, { method: 'PUT', body: JSON.stringify({ title: event.title, date: event.date, time: event.time, raw: event.raw, updatedAt: event.updatedAt, type: event.type, completed: event.completed }) }, token);
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
      setActivateStep('code');
      if (!data.code_sent) {
        setActivateError(data.error);
        setActivateCode(data.code_debug || '');
      }
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

  // ==================== 日程操作 ====================

  const startEdit = (event: ScheduleEvent) => {
    setEditingEventId(event.id);
    setEditForm({ title: event.title, date: event.date, time: event.time });
  };

  const saveEdit = async () => {
    if (!editingEventId) return;
    const existing = events.find(e => e.id === editingEventId);
    const updated: ScheduleEvent = {
      id: editingEventId,
      title: editForm.title,
      date: editForm.date,
      time: editForm.time,
      raw: existing?.raw || '',
      updatedAt: Date.now(),
      type: existing?.type || 'event',
      completed: existing?.completed || false,
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
    const rows = sorted.map(e => [e.date, e.time, e.title, e.raw]);
    const csv = ['﻿日期,开始时间,事项,备注', ...rows.map(r => r.map(c => `"${c}"`).join(','))].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = `日程表_${formatLocalDate(new Date())}.csv`; a.click();
  };

  const generateCsvTemplate = () => {
    const sample = [
      '日期,开始时间,事项,备注',
      '2026-07-20,08:50,初始训练-模拟航班,青浦B777经济静态舱',
      '2026-07-21,12:50,团队周会,C楼201',
      '2026-07-22,,整理文档',
    ].join('\n');
    const blob = new Blob(['﻿' + sample], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = 'schedule_template.csv'; a.click();
  };

  const parseImportFile = async (file: File) => {
    try {
      const ext = file.name.split('.').pop()?.toLowerCase();
      if (ext === 'csv') {
        setImportText(await file.text());
      } else if (ext === 'xlsx' || ext === 'xls') {
        const buf = await file.arrayBuffer();
        const wb = read(buf, { type: 'array' });
        const ws = wb.Sheets[wb.SheetNames[0]];
        const rows = utils.sheet_to_json<string[]>(ws, { header: 1 }) as string[][];

        // 智能检测表头映射到模板格式：日期,开始时间,事项,备注
        let header: string[] | null = null;
        let dataRows = rows;
        if (rows[0] && rows[0].some(c => String(c).includes('日期') || String(c).includes('时间') || String(c).includes('事项') || String(c).includes('内容'))) {
          header = rows[0].map(c => String(c));
          dataRows = rows.slice(1);
        }

        const findCol = (ks: string[]) => {
          if (!header) return -1;
          return header.findIndex(c => ks.some(k => c.includes(k)));
        };
        const idxD = findCol(['日期']);
        const idxT = findCol(['开始时间', '时间']);
        const idxC = findCol(['内容', '事项', '日程', '标题']);
        const idxN = findCol(['地点', '备注', '描述']);

        const csvLines = ['日期,开始时间,事项,备注'];
        for (const r of dataRows) {
          const s = r.map(c => String(c ?? '').trim());
          if (s.every(c => !c)) continue;
          const date = idxD >= 0 ? s[idxD] : s[0] || '';
          const time = idxT >= 0 ? s[idxT] : s[1] || '';
          const content = idxC >= 0 ? s[idxC] : s[2] || '';
          const note = idxN >= 0 ? s[idxN] : s[3] || '';
          if (!date && !content) continue;
          csvLines.push([date, time, content, note].map(c => c.includes(',') ? `"${c}"` : c).join(','));
        }
        setImportText(csvLines.join('\n'));
      } else {
        // PDF / docx / txt / ics / json 等→ 读为文本，交给 AI 解析
        setImportText(await file.text());
      }
    } catch { alert('文件读取失败'); }
  };

  // 上传文件/图片 → 调度器分发
  const uploadToChat = async (file: File) => {
    setShowChat(true);
    const ext = file.name.split('.').pop()?.toLowerCase();
    try {
      const result = await dispatchFileTask(file);
      if (result.type === 'IMAGE_OVERSIZE') {
        setChatMessages(prev => [...prev, { role: 'user', content: `[图片: ${file.name} 超过5MB限制，请压缩后重试]` }]);
      } else {
        setChatMessages(prev => [...prev, { role: 'user', content: result.content || '', image: result.image }]);
      }
    } catch (e) {
      if ((e as Error).message === 'PASS_THROUGH') {
        // 调度器不处理的类型（Excel / 纯文本）→ 本地处理
        try {
          if (ext === 'xlsx' || ext === 'xls') {
            const buf = await file.arrayBuffer();
            const wb = read(buf, { type: 'array' });
            const ws = wb.Sheets[wb.SheetNames[0]];
            const rows = utils.sheet_to_json<string[]>(ws, { header: 1 }) as string[][];
            const text = rows.map(r => r.map(c => String(c ?? '').trim()).join(',')).join('\n');
            setChatMessages(prev => [...prev, { role: 'user', content: `[文件: ${file.name}]\n${text.slice(0, 3000)}` }]);
          } else {
            const text = await file.text();
            setChatMessages(prev => [...prev, { role: 'user', content: `[文件: ${file.name}]\n${text.slice(0, 3000)}` }]);
          }
        } catch (e2) {
          console.error('文件读取失败:', file.name, e2);
          setChatMessages(prev => [...prev, { role: 'user', content: `[文件: ${file.name} 读取失败]` }]);
        }
      } else {
        console.error('文件读取失败:', file.name, e);
        setChatMessages(prev => [...prev, { role: 'user', content: `[文件: ${file.name} ${(e as Error).message || '读取失败'}]` }]);
      }
    }
  };

  const parseImportText = () => {
    const lines = importText.replace(/^﻿/, '').split('\n').map(l => l.trim()).filter(Boolean);
    // 跳过表头
    const startIdx = lines[0]?.startsWith('日期') ? 1 : 0;
    const preview: ScheduleEvent[] = [];

    for (let i = startIdx; i < lines.length; i++) {
      const cells = parseCsvLine(lines[i]);
      const colDate = cells[0] || '', colTime = cells[1] || '', colTitle = cells[2] || '', colNote = cells[3] || '';
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
        raw: colNote || colTitle, updatedAt: Date.now(),
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

  // ==================== AI 对话框 ====================

  const AI_BRANDS: Record<string, { name: string; endpoint: string; platform: string; billing: string; models: { id: string; label: string; price: string }[] }> = {
    deepseek: {
      name: 'DeepSeek', endpoint: 'https://api.deepseek.com/v1/chat/completions', platform: 'https://platform.deepseek.com', billing: 'https://platform.deepseek.com/usage',
      models: [
        { id: 'deepseek-v4-flash', label: 'V4 Flash', price: '¥1.0/百万token' },
        { id: 'deepseek-v4-pro', label: 'V4 Pro', price: '¥3.1/百万token' },
      ],
    },
    kimi: {
      name: 'Kimi 月之暗面', endpoint: 'https://api.moonshot.cn/v1/chat/completions', platform: 'https://platform.kimi.com', billing: 'https://platform.kimi.com/console/account',
      models: [
        { id: 'kimi-k2.6', label: 'K2.6', price: '¥4.3/百万token' },
        { id: 'kimi-k2.5', label: 'K2.5 多模态', price: '¥4.3/百万token' },
      ],
    },
    doubao: {
      name: '豆包', endpoint: 'https://ark.cn-beijing.volces.com/api/v3/chat/completions', platform: 'https://console.volcengine.com/ark', billing: 'https://console.volcengine.com/ark/region:ark+cn-beijing/billing',
      models: [
        { id: 'doubao-pro', label: 'Pro', price: '¥2.0/百万token' },
        { id: 'doubao-lite', label: 'Lite', price: '¥0.8/百万token' },
      ],
    },
    qwen: {
      name: '通义千问', endpoint: 'https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions', platform: 'https://dashscope.console.aliyun.com', billing: 'https://dashscope.console.aliyun.com/billing',
      models: [
        { id: 'qwen-turbo', label: 'Turbo', price: '¥2.0/百万token' },
        { id: 'qwen-plus', label: 'Plus', price: '¥4.0/百万token' },
      ],
    },
    glm: {
      name: '智谱 GLM', endpoint: 'https://open.bigmodel.cn/api/paas/v4/chat/completions', platform: 'https://open.bigmodel.cn', billing: 'https://open.bigmodel.cn/usercenter/proj-mgmt/apikeys',
      models: [
        { id: 'glm-4-flash', label: 'GLM-4 Flash', price: '¥0.1/百万token' },
      ],
    },
  };

  useEffect(() => {
    const saved = localStorage.getItem('schedule_ai_config');
    if (saved) { try { setAiConfig(JSON.parse(saved)); } catch { /* ignore */ } }
  }, []);

  const getSystemPrompt = () => `你是菠萝日程的AI助手。当前日期：${formatLocalDate(new Date())}。根据用户输入，调用对应函数处理日程或回复聊天。

规则：
- 有明确时间段的归为event，只说"今天/明天做XX"没有具体时间的归为task（time留空）
- "后天"=当前日期+2天，"下周X"按当前日期推算
- 闲聊或回答问题用文字直接回复，不要调用函数`;

  const CHAT_TOOLS = [{
    type: 'function' as const,
    function: {
      name: 'create_events',
      description: '创建新日程或任务。当用户描述有时间、日期的安排、计划、待办事项时调用。',
      parameters: {
        type: 'object',
        properties: {
          events: {
            type: 'array',
            description: '要创建的日程/任务列表',
            items: {
              type: 'object',
              properties: {
                date: { type: 'string', description: '日期 YYYY-MM-DD' },
                time: { type: 'string', description: '时间 HH:mm，无具体时间则留空字符串' },
                title: { type: 'string', description: '事项标题' },
                note: { type: 'string', description: '备注或补充信息' },
                type: { type: 'string', enum: ['event', 'task'], description: 'event=有明确时间段的事项, task=待办/无固定时间' },
              },
              required: ['date', 'title', 'type'],
            },
          },
          message: { type: 'string', description: '给用户的确认提示语' },
        },
        required: ['events'],
      },
    },
  }];

  const toggleRecording = () => {
    if (isRecording) {
      recognitionRef.current?.stop();
      recognitionRef.current = null;
      setIsRecording(false);
      return;
    }
    const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
    if (!SR) return;
    const r = new SR();
    r.lang = 'zh-CN';
    r.interimResults = false;
    r.continuous = false;
    r.onresult = (e: SpeechRecognitionEvent) => {
      setChatInput(prev => prev + e.results[0][0].transcript);
    };
    r.onerror = () => setIsRecording(false);
    r.onend = () => setIsRecording(false);
    r.start();
    recognitionRef.current = r;
    setIsRecording(true);
  };

  const sendChat = async () => {
    if (!chatInput.trim() || chatLoading) return;
    const userMsg = chatInput.trim();
    setChatInput('');
    setChatMessages(prev => [...prev, { role: 'user', content: userMsg }]);
    setChatLoading(true);

    try {
      const brand = AI_BRANDS[aiConfig.brand] || AI_BRANDS.deepseek;
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 60000);
      const res = await fetch(brand.endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${aiConfig.key}` },
        body: JSON.stringify({
          model: aiConfig.model,
          messages: [
            { role: 'system', content: getSystemPrompt() },
            ...chatMessages.map(m => {
              if (m.image && m.role === 'user') {
                // 图片消息：image_url 原样透传，text 标签不做 Token 截断
                return { role: 'user', content: [
                  { type: 'image_url', image_url: { url: m.image } },
                  { type: 'text', text: m.content },
                ]};
              }
              // 纯文本消息：经过 Token 防腐层
              return { role: m.role, content: adaptPayloadToModel(m.content, aiConfig.model) };
            }),
            // 当前用户输入：纯文本，经过 Token 防腐层
            { role: 'user', content: adaptPayloadToModel(userMsg, aiConfig.model) },
          ],
          tools: CHAT_TOOLS,
        }),
        signal: controller.signal,
      });
      clearTimeout(timeout);
      const data = await res.json();
      if (!res.ok) {
        const errMsg = data.error?.message || `HTTP ${res.status}`;
        setChatMessages(prev => [...prev, { role: 'assistant', content: `API 错误：${errMsg}` }]);
        setChatLoading(false);
        return;
      }
      const choice = data.choices?.[0];
      const msg = choice?.message;
      if (!msg) {
        setChatMessages(prev => [...prev, { role: 'assistant', content: 'API 返回为空，请检查 Key 和模型名称是否正确。' }]);
        setChatLoading(false);
        return;
      }

      // 函数调用 → 展示确认卡片
      if (msg.tool_calls?.length) {
        for (const tc of msg.tool_calls) {
          if (tc.function.name === 'create_events') {
            let args: { events?: Array<{ date: string; time?: string; title: string; note?: string; type: string }>; message?: string };
            try { args = JSON.parse(tc.function.arguments); } catch { continue; }
            if (args.events?.length) {
              const cards = args.events.map(ev => ({
                date: ev.date, time: ev.time || '', title: ev.title,
                type: (ev.type === 'task' ? 'task' : 'event') as 'event' | 'task',
              }));
              setChatMessages(prev => [...prev, {
                role: 'assistant',
                content: args.message || (msg.content || `已识别 ${cards.length} 条，请确认：`),
                cards,
              }]);
            }
          }
        }
        setChatLoading(false);
        return;
      }

      // 纯文本回复
      const text = msg.content || '';
      setChatMessages(prev => [...prev, { role: 'assistant', content: text || 'API 返回为空。' }]);
    } catch (e: unknown) {
      const errMsg = (e as Error)?.name === 'AbortError' ? '请求超时（60秒），请重试' : '出错了，请检查AI设置中的Key是否正确。';
      setChatMessages(prev => [...prev, { role: 'assistant', content: errMsg }]);
    } finally {
      setChatLoading(false);
    }
  };

  const confirmAiCards = (cards: { date: string; time: string; title: string; type: 'event' | 'task' }[]) => {
    for (const card of cards) {
      const ev: ScheduleEvent = {
        id: crypto.randomUUID(), title: card.title, date: card.date, time: card.time,
        raw: card.title, updatedAt: Date.now(), type: card.type, completed: false,
      };
      setEvents(prev => [...prev, ev]);
      if (isOnline && token) pushToCloud(ev, 'POST');
    }
    setChatMessages(prev => prev.filter(m => !m.cards?.length));
    if (cards[0]) setDetailDate(cards[0].date);
  };

  // ==================== 日历渲染 ====================

  const renderCalendar = () => {
    const year = currentDate.getFullYear();
    const month = currentDate.getMonth();
    const firstDay = (new Date(year, month, 1).getDay() + 6) % 7;
    const daysInMonth = new Date(year, month + 1, 0).getDate();
    const daysInPrevMonth = new Date(year, month, 0).getDate();
    const days: React.ReactNode[] = [];

    for (let i = firstDay - 1; i >= 0; i--) {
      days.push(<div key={`pv-${i}`} className="text-[#C0BDB8] text-center py-3 text-lg">{daysInPrevMonth - i}</div>);
    }

    const today = new Date();
    for (let i = 1; i <= daysInMonth; i++) {
      const d = new Date(year, month, i);
      const ds = formatLocalDate(d);
      const has = isOnline && events.some(e => e.date === ds);
      const active = formatLocalDate(selectedDate) === ds;
      const isToday = formatLocalDate(today) === ds;

      days.push(
        <button key={i} onClick={() => { setSelectedDate(d); setDetailDate(ds); }}
          className={`relative py-3 text-lg font-medium rounded-xl transition-all duration-200
            ${active ? 'bg-[#ED6A3B] text-white font-bold shadow-lg scale-105' : 'hover:bg-[#F3F1ED] text-[#1C1C1C]'}
            ${isToday && !active ? 'border-2 border-[#ED6A3B] text-[#ED6A3B] font-bold bg-[#FFF5F0]' : ''}`}
          aria-label={`${month + 1}月${i}日`}>
          {i}
          {has && <span className={`absolute bottom-1 left-1/2 -translate-x-1/2 w-1.5 h-1.5 rounded-full ${active ? 'bg-white' : 'bg-red-400'}`} />}
        </button>
      );
    }
    return days;
  };

  const dayEvents = (detailDate && isOnline)
    ? events.filter(e => e.date === detailDate && e.type !== 'task').sort((a, b) => a.time.localeCompare(b.time))
    : [];
  const dayTasks = (detailDate && isOnline)
    ? events.filter(e => e.date === detailDate && e.type === 'task')
        .sort((a, b) => (a.completed ? 1 : 0) - (b.completed ? 1 : 0) || b.updatedAt - a.updatedAt)
    : [];

  const weekDays = ['一', '二', '三', '四', '五', '六', '日'];

  // ==================== UI ====================

  return (
    <main className="min-h-screen pb-16 bg-[#F7F5F2] flex flex-col">
      {/* v1.0 更新弹窗 */}
      {showVersionModal && (
        <div className="fixed inset-0 z-[70] flex items-center justify-center bg-black/50 backdrop-blur-sm p-4" onClick={dismissVersionModal}>
          <div className="bg-white rounded-2xl w-full max-w-xs p-6 shadow-lg animate-slide-up" onClick={e => e.stopPropagation()}>
            <div className="flex items-center gap-2.5 mb-5">
              <img src="/icon-192x192.png" alt="" className="w-8 h-8 rounded-lg" />
              <div>
                <h2 className="text-lg font-bold text-[#1C1C1C] leading-tight">菠萝日程</h2>
                <span className="text-xs font-semibold text-[#ED6A3B]">v2.0</span>
              </div>
            </div>

            <div className="space-y-3 mb-6 text-xs text-[#5C5C5C]">
              <div className="flex gap-2.5"><span className="text-sm shrink-0">AI 助理</span><span className="text-[#A0A0A0]">右下角点 💬 对话创建/查询日程 · 支持 DeepSeek 等</span></div>
              <div className="flex gap-2.5"><span className="text-sm shrink-0">每日任务</span><span className="text-[#A0A0A0]">无时间的待办自动归为任务 · 完成后划线保留</span></div>
              <div className="flex gap-2.5"><span className="text-sm shrink-0">文件导入</span><span className="text-[#A0A0A0]">📎 上传或拖入 CSV/Excel/PDF · 预览后确认</span></div>
              <div className="flex gap-2.5"><span className="text-sm shrink-0">多设备同步</span><span className="text-[#A0A0A0]">邮箱激活 · 30 秒自动同步</span></div>
              <div className="flex gap-2.5"><span className="text-sm shrink-0">苹果日历</span><span className="text-[#A0A0A0]">扫码订阅 · 15 分钟自动刷新</span></div>
              <div className="flex gap-2.5"><span className="text-sm shrink-0">安全防护</span><span className="text-[#A0A0A0]">CORS 白名单 · 限流 · CSP · JWT 短期</span></div>
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
          <h1 className="text-lg font-semibold text-[#1C1C1C] flex items-center gap-2 tracking-tight shrink-0">
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
            <button onClick={() => setShowAiSettings(true)}
              className="w-9 h-9 rounded-lg hover:bg-[#F3F1ED] transition-colors flex items-center justify-center" aria-label="AI设置" title="AI 连接设置">
              <span className="text-base">⚙</span>
            </button>
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
                <p className="text-sm text-[#5C5C5C] leading-relaxed">直接输入自然语言，如「<span className="text-[#ED6A3B]">后天下午3点买菜</span>」「<span className="text-[#ED6A3B]">本周五上午10点开会</span>」，回车即保存。日期、时间自动识别。<br /><span className="text-xs text-[#A0A0A0]">支持换行分隔，一次输入多个日程</span></p>
              </div>

              <div>
                <h3 className="text-sm font-semibold text-[#1C1C1C] mb-1.5">添加到桌面</h3>
                <p className="text-sm text-[#5C5C5C] leading-relaxed">iPhone Safari 点分享按钮 → 添加到主屏幕<br />Android Chrome 点菜单 → 添加到主屏幕<br /><span className="text-xs text-[#A0A0A0]">添加后像 App 一样打开，体验更流畅</span></p>
              </div>

              <div>
                <h3 className="text-sm font-semibold text-[#1C1C1C] mb-1.5">语音输入</h3>
                <p className="text-sm text-[#5C5C5C] leading-relaxed">按住麦克风按钮说话，松手后文字自动填入输入框。确认无误点发送保存。<br /><span className="text-xs text-[#A0A0A0]">Chrome / Edge 浏览器可用，iPhone 用键盘自带听写</span></p>
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
                        <select value={e.type} onChange={ev => {
                          const next = [...importPreview]; next[i] = { ...next[i], type: ev.target.value as 'event' | 'task', time: ev.target.value === 'task' ? '' : next[i].time }; setImportPreview(next);
                        }} className="px-2 py-1 border border-[#E8E4DF] rounded text-xs bg-white outline-none">
                          <option value="event">日程</option>
                          <option value="task">任务</option>
                        </select>
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
                  <p className="text-xs text-[#A0A0A0]">每行一条，格式：日期,开始时间,事项,备注（无时间的自动归为任务）</p>
                  <textarea value={importText} onChange={e => setImportText(e.target.value)}
                    placeholder={`2026-07-20,08:50,初始训练-模拟航班,青浦B777经济静态舱\n2026-07-21,12:50,团队周会,C楼201\n2026-07-22,,整理文档`}
                    className="flex-1 w-full p-3 border border-[#E8E4DF] rounded-lg text-sm outline-none focus:border-[#1C1C1C] resize-none font-mono" />
                  <div className="flex gap-2">
                    <label className="flex-1 h-11 rounded-lg border border-dashed border-[#D9D4CF] text-sm text-[#5C5C5C] hover:bg-[#F3F1ED] transition-colors flex items-center justify-center gap-1.5 cursor-pointer">
                      <Upload className="w-4 h-4" /> 上传 CSV / XLSX
                      <input type="file" accept=".csv,.xlsx" onChange={e => { if (e.target.files?.[0]) parseImportFile(e.target.files[0]); e.target.value = ''; }} className="hidden" />
                    </label>
                    <button onClick={generateCsvTemplate}
                      className="h-11 px-4 rounded-lg border border-[#E8E4DF] text-sm text-[#5C5C5C] hover:bg-[#F3F1ED] transition-colors flex items-center gap-1.5">
                      <Download className="w-4 h-4" /> 下载模板
                    </button>
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
                          </div>
                          <div className="flex gap-3">
                            <div className="flex-1">
                              <label className="text-xs text-[#A0A0A0] mb-1 block">日期</label>
                              <input type="date" title="日期" value={editForm.date} onChange={ev => setEditForm({ ...editForm, date: ev.target.value })}
                                className="w-full px-3 py-2 border border-[#E8E4DF] rounded-lg text-sm outline-none focus:border-[#1C1C1C]" />
                            </div>
                            <div className="flex-1">
                              <label className="text-xs text-[#A0A0A0] mb-1 block">时间</label>
                              <input type="time" title="时间" value={editForm.time} onChange={ev => setEditForm({ ...editForm, time: ev.target.value })}
                                className="w-full px-3 py-2 border border-[#E8E4DF] rounded-lg text-sm outline-none focus:border-[#1C1C1C]" />
                            </div>
                          </div>
                          <div className="flex gap-2 justify-end">
                            <button onClick={() => { setEditingEventId(null); setEditForm({ title: '', date: '', time: '' }); }}
                              className="px-4 py-1.5 text-sm text-[#5C5C5C] bg-[#E8E4DF] rounded-lg hover:bg-[#D9D4CF] transition-colors">取消</button>
                            <button onClick={saveEdit} className="px-4 py-1.5 text-sm text-white bg-[#ED6A3B] rounded-lg hover:bg-[#D45D2E] transition-colors">保存</button>
                          </div>
                        </div>
                      ) : (
                        <div className="flex items-center gap-3">
                          <span className="bg-[#ED6A3B] text-white text-sm px-3 py-1.5 rounded-lg font-mono font-semibold min-w-[60px] text-center">{e.time}</span>
                          <div className="flex-1 min-w-0">
                            <div className="font-medium text-[#1C1C1C] truncate">{e.title}</div>
                            <div className="text-xs text-[#A0A0A0] mt-0.5 truncate">{e.raw}</div>
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
                          <div className="flex gap-2 justify-end">
                            <button onClick={() => { setEditingEventId(null); setEditForm({ title: '', date: '', time: '' }); }}
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
                            <div className={`font-medium truncate ${e.completed ? 'line-through text-[#A0A0A0]' : 'text-[#1C1C1C]'}`}>{e.title}</div>
                            {e.raw && <div className={`text-xs mt-0.5 truncate ${e.completed ? 'line-through text-[#C0BDB8]' : 'text-[#A0A0A0]'}`}>{e.raw}</div>}
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

      {/* Calendar */}
      <div className={`bg-white rounded-2xl p-5 shadow-sm border border-[#E8E4DF] overflow-y-auto ${detailDate ? 'md:w-3/4' : 'md:w-full'}`}>
        <div className="flex justify-between items-center mb-5">
          <h2 className="text-lg font-bold text-[#1C1C1C]">
            {currentDate.getFullYear()}年{currentDate.getMonth() + 1}月
          </h2>
          <div className="flex gap-2">
            <button onClick={() => setCurrentDate(d => new Date(d.getFullYear(), d.getMonth() - 1))}
              className="w-9 h-9 bg-[#F3F1ED] hover:bg-[#E8E4DF] rounded-full text-[#5C5C5C] flex items-center justify-center transition-colors" aria-label="上个月">
              <ChevronLeft className="w-5 h-5" />
            </button>
            <button onClick={() => setCurrentDate(d => new Date(d.getFullYear(), d.getMonth() + 1))}
              className="w-9 h-9 bg-[#F3F1ED] hover:bg-[#E8E4DF] rounded-full text-[#5C5C5C] flex items-center justify-center transition-colors" aria-label="下个月">
              <ChevronRight className="w-5 h-5" />
            </button>
          </div>
        </div>

        <div className="grid grid-cols-7 gap-1 mb-3">
          {weekDays.map(d => <div key={d} className="text-center text-xs text-[#A0A0A0] py-2 font-medium">{d}</div>)}
        </div>

        <div className="grid grid-cols-7 gap-1">
          {renderCalendar()}
        </div>
      </div>

      </div>

      {/* 浮动切换按钮 */}
      {!showChat && (
        <button onClick={() => setShowChat(true)}
          className="fixed bottom-28 right-4 z-50 w-14 h-14 bg-[#1C1C1C] text-white rounded-2xl shadow-lg hover:bg-[#333] transition-all flex items-center justify-center">
          <MessageCircle className="w-6 h-6" />
        </button>
      )}

      {/* AI 对话框 */}
      {showChat && (
        <div className="fixed inset-x-0 bottom-0 z-50 flex flex-col" style={{ height: '66vh' }}
          onDragOver={e => { e.preventDefault(); e.stopPropagation(); }}
          onDrop={e => { e.preventDefault(); e.stopPropagation(); const file = e.dataTransfer.files?.[0]; if (file) uploadToChat(file); }}>
          {/* 日历遮罩（点击关闭） */}
          <div className="absolute inset-0 -z-10" onClick={() => setShowChat(false)} />

          <div className="flex-1 flex flex-col bg-white rounded-t-2xl shadow-[0_-10px_40px_rgba(0,0,0,0.15)] animate-slide-up">
            {/* 对话框 Header */}
            <div className="flex items-center justify-between px-5 py-3 border-b border-[#E8E4DF] shrink-0">
              <div className="flex items-center gap-2">
                <span className="font-semibold text-sm text-[#1C1C1C]">AI 助理</span>
                {aiConfig.key ? (
                  <span className="text-xs text-[#A0A0A0]">{AI_BRANDS[aiConfig.brand]?.name} · {aiConfig.model}</span>
                ) : (
                  <span className="text-xs text-red-400">未设置 API Key</span>
                )}
              </div>
              <div className="flex items-center gap-1">
                {aiConfig.key && (
                  <a href={AI_BRANDS[aiConfig.brand]?.billing || '#'} target="_blank" rel="noopener"
                    className="w-8 h-8 rounded-lg hover:bg-[#F3F1ED] text-[#A0A0A0] flex items-center justify-center text-xs" title="查看费用明细">
                    <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><rect x="2" y="4" width="20" height="16" rx="2" strokeWidth={2}/><path d="M12 9v4M12 17h.01" strokeWidth={2.5} strokeLinecap="round"/></svg>
                  </a>
                )}
                <button onClick={() => setShowChat(false)} className="w-8 h-8 rounded-lg hover:bg-[#F3F1ED] text-[#A0A0A0] flex items-center justify-center"><X className="w-4 h-4" /></button>
              </div>
            </div>

            {/* 消息区 */}
            <div className="flex-1 overflow-y-auto px-4 py-3 space-y-3">
              {chatMessages.length === 0 && (
                <p className="text-[#A0A0A0] text-sm text-center py-8">和菠萝聊聊你的日程吧</p>
              )}
              {chatMessages.map((m, i) => (
                <div key={i} className={`flex ${m.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                  <div className={`max-w-[80%] rounded-2xl px-4 py-2.5 text-sm ${
                    m.role === 'user' ? 'bg-[#ED6A3B] text-white' : 'bg-[#F3F1ED] text-[#1C1C1C]'
                  }`}>
                    {m.image ? (
                      <div className="space-y-1.5">
                        <img src={m.image} alt="" className="max-w-[200px] max-h-[200px] rounded-lg object-cover" />
                        <p className="text-xs opacity-80">{m.content.replace('[图片: ', '').replace(']', '')}</p>
                      </div>
                    ) : m.content.startsWith('[文件:') || m.content.startsWith('[PDF:') ? (
                      <div className="flex items-center gap-2">
                        <svg className="w-5 h-5 shrink-0 opacity-70" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z"/></svg>
                        <span className="truncate text-xs">{m.content.split('\n')[0].replace('[文件: ', '').replace('[PDF: ', '').replace(']', '')}</span>
                      </div>
                    ) : (
                      <p className="whitespace-pre-wrap">{m.content}</p>
                    )}
                    {m.cards && m.cards.length > 0 && (
                      <div className="mt-2 space-y-2">
                        {m.cards.map((card, ci) => (
                          <div key={ci} className="p-2.5 bg-white rounded-xl border border-[#E8E4DF]">
                            <div className="text-xs text-[#5C5C5C] space-y-0.5 mb-2">
                              <div>{card.date} {card.time || '全天'}</div>
                              <div className="font-medium text-[#1C1C1C]">{card.title}</div>
                              <div className="text-[#A0A0A0]">{card.type === 'task' ? '任务' : '日程'}</div>
                            </div>
                            <div className="flex gap-2">
                              <button onClick={() => setChatMessages(prev => {
                                const msg = prev[i];
                                if (!msg.cards || msg.cards.length <= 1) return prev.filter((_, j) => j !== i);
                                return prev.map((m, j) => j === i ? { ...m, cards: m.cards!.filter((_, k) => k !== ci) } : m);
                              })}
                                className="flex-1 h-8 text-xs border border-[#E8E4DF] rounded-lg hover:bg-[#F3F1ED]">取消</button>
                              <button onClick={() => { confirmAiCards([card]); setChatMessages(prev => {
                                const msg = prev[i];
                                if (!msg.cards || msg.cards.length <= 1) return prev.filter((_, j) => j !== i);
                                return prev.map((m, j) => j === i ? { ...m, cards: m.cards!.filter((_, k) => k !== ci) } : m);
                              }); }}
                                className="flex-1 h-8 text-xs bg-[#ED6A3B] text-white rounded-lg hover:bg-[#D45D2E]">确认添加</button>
                            </div>
                          </div>
                        ))}
                        {m.cards.length > 1 && (
                          <button onClick={() => { confirmAiCards(m.cards!); setChatMessages(prev => prev.filter((_, j) => j !== i)); }}
                            className="w-full h-8 text-xs bg-[#ED6A3B] text-white rounded-lg hover:bg-[#D45D2E] font-medium">全部确认（{m.cards.length}条）</button>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              ))}
              {chatLoading && (
                <div className="flex justify-start">
                  <div className="bg-[#F3F1ED] rounded-2xl px-4 py-2.5">
                    <div className="flex gap-1.5">
                      <span className="w-2 h-2 rounded-full bg-[#D9D4CF] animate-bounce" style={{ animationDelay: '0ms' }} />
                      <span className="w-2 h-2 rounded-full bg-[#D9D4CF] animate-bounce" style={{ animationDelay: '150ms' }} />
                      <span className="w-2 h-2 rounded-full bg-[#D9D4CF] animate-bounce" style={{ animationDelay: '300ms' }} />
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* 输入区 */}
            <div className="px-4 py-3 border-t border-[#E8E4DF] shrink-0">
              <div className="flex items-center gap-2 bg-[#F3F1ED] p-1.5 rounded-2xl">
                {/* ＋上传 */}
                <div className="relative">
                  <button onClick={() => setShowPlusMenu(!showPlusMenu)}
                    className="w-10 h-10 rounded-xl hover:bg-[#E8E4DF] text-[#5C5C5C] flex items-center justify-center shrink-0 transition-colors">
                    <Plus className="w-5 h-5" />
                  </button>
                  {showPlusMenu && (
                    <>
                      <div className="fixed inset-0 z-[59]" onClick={() => setShowPlusMenu(false)} />
                      <div className="absolute bottom-12 left-0 bg-white rounded-2xl shadow-xl border border-[#E8E4DF] py-2 min-w-[140px] z-[60] animate-slide-up">
                      <label className="flex items-center gap-3 px-4 py-3 hover:bg-[#F7F5F2] cursor-pointer text-sm text-[#1C1C1C]">
                        <svg className="w-5 h-5 text-[#ED6A3B]" fill="none" stroke="currentColor" viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="18" rx="2" strokeWidth={2}/><circle cx="8.5" cy="8.5" r="1.5" fill="currentColor"/><path d="M21 15l-5-5L5 21" strokeWidth={2}/></svg>
                        照片
                        <input ref={photoInputRef} type="file" accept="image/*" capture="environment" onChange={e => { if (e.target.files?.[0]) { uploadToChat(e.target.files[0]); setShowPlusMenu(false); } e.target.value = ''; }} className="hidden" />
                      </label>
                      <label className="flex items-center gap-3 px-4 py-3 hover:bg-[#F7F5F2] cursor-pointer text-sm text-[#1C1C1C]">
                        <svg className="w-5 h-5 text-[#5C5C5C]" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z"/></svg>
                        文件
                        <input ref={fileInputRef} type="file" accept=".csv,.xlsx,.xls,.pdf,.txt,.docx,.ics,.json" onChange={e => { if (e.target.files?.[0]) { uploadToChat(e.target.files[0]); setShowPlusMenu(false); } e.target.value = ''; }} className="hidden" />
                      </label>
                      <button onClick={() => { generateCsvTemplate(); setShowPlusMenu(false); }}
                        className="flex items-center gap-3 px-4 py-3 hover:bg-[#F7F5F2] w-full text-left text-sm text-[#1C1C1C]">
                        <svg className="w-5 h-5 text-[#A0A0A0]" fill="none" stroke="currentColor" viewBox="0 0 24 24"><rect x="3" y="5" width="18" height="16" rx="1" strokeWidth={2}/><path d="M3 5h18M8 5v16M3 10h18" strokeWidth={2}/></svg>
                        模板
                      </button>
                    </div>
                    </>
                  )}
                </div>
                {/* 语音 */}
                <button onClick={toggleRecording}
                  className={`w-10 h-10 rounded-xl flex items-center justify-center shrink-0 transition-all ${
                    isRecording ? 'bg-red-500 text-white animate-pulse' : 'hover:bg-[#E8E4DF] text-[#5C5C5C]'
                  }`}>
                  <Mic className="w-5 h-5" />
                </button>
                <input type="text" value={chatInput} onChange={e => setChatInput(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && sendChat()}
                  placeholder="和菠萝聊聊日程..." disabled={!aiConfig.key}
                  className="flex-1 bg-transparent px-2 py-2.5 text-[#1C1C1C] outline-none text-sm placeholder:text-[#A0A0A0] disabled:opacity-40" />
                <button onClick={sendChat} disabled={!chatInput.trim() || chatLoading || !aiConfig.key}
                  className="w-10 h-10 bg-[#ED6A3B] hover:bg-[#D45D2E] disabled:opacity-40 rounded-xl text-white flex items-center justify-center shrink-0 transition-all">
                  <Send className="w-4 h-4" />
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* AI 设置弹窗 */}
      {showAiSettings && (
        <div className="fixed inset-0 z-[70] flex items-center justify-center bg-black/40 backdrop-blur-sm p-4" onClick={() => setShowAiSettings(false)}>
          <div className="bg-white rounded-2xl w-full max-w-sm p-6 shadow-lg max-h-[85vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
            <div className="flex justify-between items-center mb-5">
              <h2 className="font-semibold text-[#1C1C1C]">AI 连接设置</h2>
              <button onClick={() => setShowAiSettings(false)} className="w-8 h-8 rounded-lg hover:bg-[#F3F1ED] text-[#A0A0A0] flex items-center justify-center">&times;</button>
            </div>

            {/* 品牌选择（卡片式） */}
            <label className="text-xs text-[#A0A0A0] mb-2 block">选择品牌</label>
            <div className="space-y-1.5 mb-4">
              {Object.entries(AI_BRANDS).map(([k, b]) => (
                <button key={k} onClick={() => { const m = b.models[0]?.id || ''; const c = { ...aiConfig, brand: k, model: m }; setAiConfig(c); localStorage.setItem('schedule_ai_config', JSON.stringify(c)); }}
                  className={`w-full flex items-center justify-between p-3 rounded-xl border transition-colors ${
                    aiConfig.brand === k ? 'border-[#ED6A3B] bg-[#FFF5F0]' : 'border-[#E8E4DF] hover:bg-[#F7F5F2]'
                  }`}>
                  <div className="text-left">
                    <div className="text-sm font-medium text-[#1C1C1C]">{b.name}</div>
                    <div className="text-xs text-[#A0A0A0] mt-0.5">{b.models.map(m => m.label).join(' / ')} · {b.models[0]?.price}</div>
                  </div>
                  <a href={b.platform} target="_blank" rel="noopener" onClick={e => e.stopPropagation()}
                    className="text-xs text-[#A0A0A0] hover:text-[#ED6A3B] underline shrink-0 ml-2">官网</a>
                </button>
              ))}
            </div>

            {/* 模型选择 */}
            <label className="text-xs text-[#A0A0A0] mb-2 block">模型版本</label>
            <div className="space-y-1.5 mb-4">
              {(AI_BRANDS[aiConfig.brand]?.models || []).map(m => (
                <button key={m.id} onClick={() => { const c = { ...aiConfig, model: m.id }; setAiConfig(c); localStorage.setItem('schedule_ai_config', JSON.stringify(c)); }}
                  className={`w-full flex items-center justify-between p-3 rounded-xl border transition-colors ${
                    aiConfig.model === m.id ? 'border-[#ED6A3B] bg-[#FFF5F0]' : 'border-[#E8E4DF] hover:bg-[#F7F5F2]'
                  }`}>
                  <div className="text-left">
                    <div className="text-sm font-medium text-[#1C1C1C]">{m.label}</div>
                    <div className="text-xs text-[#A0A0A0]">{m.id}</div>
                  </div>
                  <span className="text-xs text-[#5C5C5C]">{m.price}</span>
                </button>
              ))}
            </div>

            {/* API Key */}
            <label className="text-xs text-[#A0A0A0] mb-2 block">API Key</label>
            <div className="flex gap-2 mb-4">
              <input type="password" value={aiConfig.key} onChange={e => { const c = { ...aiConfig, key: e.target.value }; setAiConfig(c); localStorage.setItem('schedule_ai_config', JSON.stringify(c)); }}
                placeholder="sk-..." className="flex-1 px-3 py-2.5 border border-[#E8E4DF] rounded-lg text-sm outline-none focus:border-[#1C1C1C]" />
              <a href={AI_BRANDS[aiConfig.brand]?.billing || '#'} target="_blank" rel="noopener"
                className="shrink-0 h-10 px-3 rounded-lg border border-[#E8E4DF] text-xs text-[#5C5C5C] hover:bg-[#F3F1ED] transition-colors flex items-center gap-1">
                费用明细 ↗
              </a>
            </div>

            <button onClick={() => setShowAiSettings(false)}
              className="w-full h-11 bg-[#1C1C1C] text-white rounded-lg text-sm font-semibold hover:bg-[#333] transition-colors">完成</button>
          </div>
        </div>
      )}
    </main>
  );
}
