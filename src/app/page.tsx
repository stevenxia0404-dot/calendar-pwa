'use client';

import { useState, useEffect, useCallback, useRef } from 'react';
import { Mic, Send, ChevronLeft, ChevronRight, Download, LogOut, RefreshCw, Mail } from 'lucide-react';

// ==================== 配置 ====================

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'https://schedule-api.boluomate.com';

// ==================== 工具函数 ====================

function formatLocalDate(date: Date): string {
  const y = date.getFullYear();
  const m = String(date.getMonth() + 1).padStart(2, '0');
  const d = String(date.getDate()).padStart(2, '0');
  return `${y}-${m}-${d}`;
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
}

interface User { id: number; email: string; }

// ==================== 主组件 ====================

export default function Home() {
  // 日程状态
  const [events, setEvents] = useState<ScheduleEvent[]>([]);
  const [currentDate, setCurrentDate] = useState(new Date());
  const [selectedDate, setSelectedDate] = useState(new Date());
  const [inputText, setInputText] = useState('');
  const [isProcessing, setIsProcessing] = useState(false);
  const [detailDate, setDetailDate] = useState<string | null>(null);
  const [editingEventId, setEditingEventId] = useState<string | null>(null);
  const [editForm, setEditForm] = useState({ title: '', date: '', time: '' });

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
  const [showVersionBanner, setShowVersionBanner] = useState(false);
  const [showFeedback, setShowFeedback] = useState(false);
  const [feedbackText, setFeedbackText] = useState('');
  const [feedbackSent, setFeedbackSent] = useState(false);
  const [showHelp, setShowHelp] = useState(false);

  // 版本 Banner
  useEffect(() => {
    const seen = localStorage.getItem('schedule_version_seen');
    if (seen !== 'v0.4.0') setShowVersionBanner(true);
  }, []);

  const dismissBanner = () => {
    localStorage.setItem('schedule_version_seen', 'v0.4.0');
    setShowVersionBanner(false);
  };

  const submitFeedback = async () => {
    if (!feedbackText.trim()) return;
    try {
      await api('/feedback', { method: 'POST', body: JSON.stringify({ text: feedbackText, email: user?.email || '' }) }, token);
      setFeedbackSent(true);
      setTimeout(() => { setShowFeedback(false); setFeedbackSent(false); setFeedbackText(''); }, 2000);
    } catch { /* ignore */ }
  };

  // 示例轮播
  const placeholders = [
    '后天下午3点买菜',
    '本周五上午10点开会',
    '下周三晚上7点聚餐',
    '下个月15号体检',
  ];
  const [phIndex, setPhIndex] = useState(0);
  useEffect(() => {
    const t = setInterval(() => setPhIndex(i => (i + 1) % placeholders.length), 4000);
    return () => clearInterval(t);
  }, []);

  // 语音状态
  const [isRecording, setIsRecording] = useState(false);
  const [willCancel, setWillCancel] = useState(false);
  const recognitionRef = useRef<SpeechRecognition | null>(null);
  const micBtnRef = useRef<HTMLButtonElement | null>(null);

  const isOnline = !!user && !!token;

  // ==================== 初始化 ====================

  useEffect(() => {
    const saved = localStorage.getItem('schedule_events');
    if (saved) { try { setEvents(JSON.parse(saved)); } catch { /* ignore */ } }

    const savedToken = localStorage.getItem('schedule_token');
    if (savedToken) setToken(savedToken);
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
        if (!since) {
          // 全量同步：云端为准
          return cloudEvents.map((ce: { id: string; title: string; date: string; time: string; raw: string; updated_at: number }) => ({
            id: ce.id, title: ce.title, date: ce.date, time: ce.time,
            raw: ce.raw || '', updatedAt: ce.updated_at
          }));
        }
        // 增量同步：合并
        const map = new Map(prev.map(e => [e.id, e]));
        for (const ce of cloudEvents) {
          const local = map.get(ce.id);
          if (!local || ce.updated_at > local.updatedAt) {
            map.set(ce.id, { id: ce.id, title: ce.title, date: ce.date, time: ce.time, raw: ce.raw || '', updatedAt: ce.updated_at });
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
        await api(`/events/${event.id}`, { method: 'PUT', body: JSON.stringify({ title: event.title, date: event.date, time: event.time, raw: event.raw, updatedAt: event.updatedAt }) }, token);
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

  // ==================== 语音识别 ====================

  const speechSupported = typeof window !== 'undefined' && !!(window.SpeechRecognition || window.webkitSpeechRecognition);

  const startRecording = useCallback(() => {
    const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
    if (!SR) return;
    const r = new SR();
    r.lang = 'zh-CN';
    r.interimResults = false;
    r.continuous = false;

    r.onresult = (e: SpeechRecognitionEvent) => {
      setInputText(e.results[0][0].transcript);
    };

    r.onerror = () => { setIsRecording(false); setWillCancel(false); };
    r.onend = () => { setIsRecording(false); setWillCancel(false); };

    r.start();
    recognitionRef.current = r;
    setIsRecording(true);
    setWillCancel(false);
  }, []);

  const stopRecording = useCallback(() => {
    recognitionRef.current?.stop();
    recognitionRef.current = null;
    setIsRecording(false);
  }, []);

  // 移动端用 touch，桌面端用 pointer
  const pressStart = (e: React.TouchEvent | React.PointerEvent) => {
    e.preventDefault();
    startRecording();
  };

  const pressEnd = (e: React.TouchEvent | React.PointerEvent) => {
    e.preventDefault();
    if (willCancel) { stopRecording(); setWillCancel(false); return; }
    stopRecording();
    // 语音识别结果填入输入框，不自动提交——让用户确认后再发送
  };

  const pressMove = (e: React.PointerEvent | React.TouchEvent) => {
    if (!isRecording || !micBtnRef.current) return;
    const btn = micBtnRef.current;
    const rect = btn.getBoundingClientRect();
    const margin = 50;
    const clientX = 'touches' in e ? e.touches[0].clientX : e.clientX;
    const clientY = 'touches' in e ? e.touches[0].clientY : e.clientY;
    const outside = clientX < rect.left - margin || clientX > rect.right + margin ||
                    clientY < rect.top - margin || clientY > rect.bottom + margin;
    setWillCancel(outside);
  };

  // ==================== 日程操作 ====================

  const handleSubmit = useCallback(async () => {
    if (isProcessing || !inputText.trim()) return;
    setIsProcessing(true);

    const text = inputText.trim();
    const smartDate = parseSmartDate(text);
    const date = smartDate || new Date(selectedDate);
    const timeObj = extractTime(text);

    // 标题：去掉日期词和时间词后的剩余
    const title = text
      .replace(/今天|明天|后天|大后天|下周|本周|\d{1,2}[号日]|(上午|下午|晚上|早上)?\s*\d{1,2}\s*[点:：]\s*\d{0,2}\s*[分]?|\d+天后|\d+月\d+[号日]|下个月\d+[号日]/g, '')
      .trim() || '新日程';

    const newEvent: ScheduleEvent = {
      id: crypto.randomUUID(),
      title,
      date: formatLocalDate(date),
      time: timeObj.str,
      raw: text,
      updatedAt: Date.now(),
    };

    setEvents(prev => [...prev, newEvent]);
    setInputText('');
    setIsProcessing(false);
    setDetailDate(formatLocalDate(date));
    if (isOnline && token) pushToCloud(newEvent, 'POST');
  }, [inputText, isProcessing, selectedDate, isOnline, token]);

  const startEdit = (event: ScheduleEvent) => {
    setEditingEventId(event.id);
    setEditForm({ title: event.title, date: event.date, time: event.time });
  };

  const saveEdit = async () => {
    if (!editingEventId) return;
    const updated: ScheduleEvent = {
      id: editingEventId,
      title: editForm.title,
      date: editForm.date,
      time: editForm.time,
      raw: events.find(e => e.id === editingEventId)?.raw || '',
      updatedAt: Date.now(),
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

  const handleExport = () => {
    const sorted = [...events].sort((a, b) => a.date.localeCompare(b.date));
    const rows = sorted.map(e => [e.date, e.time, e.title, e.raw]);
    const csv = ['﻿日期,时间,事项,原始输入', ...rows.map(r => r.map(c => `"${c}"`).join(','))].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = `日程表_${formatLocalDate(new Date())}.csv`; a.click();
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
      days.push(<div key={`pv-${i}`} className="text-[#A0A0A0] text-center py-2 text-sm">{daysInPrevMonth - i}</div>);
    }

    const today = new Date();
    for (let i = 1; i <= daysInMonth; i++) {
      const d = new Date(year, month, i);
      const ds = formatLocalDate(d);
      const has = events.some(e => e.date === ds);
      const active = formatLocalDate(selectedDate) === ds;
      const isToday = formatLocalDate(today) === ds;

      days.push(
        <button key={i} onClick={() => { setSelectedDate(d); setDetailDate(ds); }}
          className={`relative py-2 text-sm rounded-xl transition-all duration-200
            ${active ? 'bg-[#ED6A3B] text-white font-bold shadow-lg scale-105' : 'hover:bg-[#F3F1ED] text-[#5C5C5C]'}
            ${isToday && !active ? 'border-2 border-[#ED6A3B] text-[#ED6A3B] font-bold bg-[#FFF5F0]' : ''}`}
          aria-label={`${month + 1}月${i}日`}>
          {i}
          {has && <span className={`absolute bottom-1 left-1/2 -translate-x-1/2 w-1.5 h-1.5 rounded-full ${active ? 'bg-white' : 'bg-red-400'}`} />}
        </button>
      );
    }
    return days;
  };

  const dayEvents = detailDate
    ? events.filter(e => e.date === detailDate).sort((a, b) => a.time.localeCompare(b.time))
    : [];

  const weekDays = ['一', '二', '三', '四', '五', '六', '日'];

  // ==================== UI ====================

  return (
    <main className="min-h-screen pb-44 bg-[#F7F5F2] flex flex-col">
      {/* 版本公告 */}
      {showVersionBanner && (
        <div className="bg-[#1C1C1C] text-white px-5 py-3 text-sm flex items-center justify-between">
          <span><span className="text-[#ED6A3B] font-semibold">v0.4.0</span> 语音输入 · 日历订阅 · 自动同步 · 全新界面</span>
          <button onClick={dismissBanner} className="text-white/60 hover:text-white ml-3 text-lg leading-none">&times;</button>
        </div>
      )}

      {/* Header */}
      <header className="bg-white px-5 py-4 sticky top-0 z-50 border-b border-[#E8E4DF]">
        <div className="flex justify-between items-center max-w-md mx-auto">
          <h1 className="text-lg font-semibold text-[#1C1C1C] flex items-center gap-2 tracking-tight">
            <img src="/icon-192x192.png" alt="" className="w-7 h-7 rounded" /> 菠萝日程
          </h1>
          <div className="flex items-center gap-1">
            <div className="relative group">
              <span className={`w-2.5 h-2.5 rounded-full block cursor-default ${isOnline ? 'bg-[#059669] shadow-[0_0_6px_rgba(5,150,105,0.4)]' : 'bg-[#D9D4CF]'}`} />
              <div className="absolute right-0 top-6 hidden group-hover:block bg-[#1C1C1C] text-white text-xs rounded-lg px-3 py-2 whitespace-nowrap z-50 shadow-lg">
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
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/30" onClick={() => { if (!activateLoading) { setShowActivate(false); setActivateStep('email'); setActivateError(''); } }}>
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
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/30" onClick={() => { setShowCalModal(false); setIcalCopied(false); }}>
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
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/30" onClick={() => { setShowFeedback(false); setFeedbackSent(false); setFeedbackText(''); }}>
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
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm" onClick={() => setShowHelp(false)}>
          <div className="bg-white rounded-2xl p-6 mx-4 w-full max-w-sm shadow-lg max-h-[80vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
            <div className="flex justify-between items-center mb-5">
              <h2 className="text-lg font-semibold text-[#1C1C1C]">使用说明</h2>
              <button onClick={() => setShowHelp(false)} className="w-8 h-8 rounded-lg hover:bg-[#F3F1ED] text-[#A0A0A0] flex items-center justify-center transition-colors">&times;</button>
            </div>

            <div className="space-y-5">
              <div>
                <h3 className="text-sm font-semibold text-[#1C1C1C] mb-1.5">快速记录</h3>
                <p className="text-sm text-[#5C5C5C] leading-relaxed">直接输入自然语言，如「<span className="text-[#ED6A3B]">后天下午3点买菜</span>」「<span className="text-[#ED6A3B]">本周五上午10点开会</span>」，回车即保存。日期、时间自动识别。</p>
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

      {/* 激活成功提示 */}
      {activateSuccess && (
        <div className="fixed top-20 left-1/2 -translate-x-1/2 z-50 bg-[#1C1C1C] text-white px-5 py-3 rounded-xl shadow-lg text-sm font-medium animate-bounce">
          激活成功！数据自动同步中
        </div>
      )}

      {/* Detail Card */}
      {detailDate && (
        <div className="mx-4 mt-3 bg-white rounded-2xl p-5 shadow-sm border border-[#E8E4DF] order-2">
          <div className="flex justify-between items-center mb-4">
            <h2 className="font-semibold text-[#1C1C1C]">{detailDate} 日程</h2>
            <button onClick={() => setDetailDate(null)}
              className="w-8 h-8 bg-[#F3F1ED] hover:bg-[#E8E4DF] rounded-lg text-[#A0A0A0] flex items-center justify-center transition-colors" aria-label="关闭">
              ×
            </button>
          </div>
          {dayEvents.length === 0 ? (
            <p className="text-[#A0A0A0] text-center py-8 text-sm">暂无日程，在下方输入</p>
          ) : (
            <div className="space-y-3">
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
        </div>
      )}

      {/* Calendar */}
      <div className="mx-4 mt-3 bg-white rounded-2xl p-5 shadow-sm border border-[#E8E4DF] order-1">
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

      {/* 底部输入栏 */}
      <div className="fixed bottom-0 left-0 right-0 bg-white/95 backdrop-blur-lg px-4 py-4 pb-8 shadow-[0_-10px_40px_rgba(0,0,0,0.15)] rounded-t-3xl border-t border-white/30 z-50">
        {/* 录音状态提示 */}
        {isRecording && (
          <div className={`text-center mb-3 text-sm font-medium transition-colors ${willCancel ? 'text-red-500' : 'text-[#ED6A3B] animate-pulse'}`}>
            {willCancel ? '松开取消' : '正在听...'}
          </div>
        )}

        <div className="flex items-center gap-2 bg-[#F3F1ED]/80 p-1.5 rounded-2xl border border-transparent focus-within:border-[#ED6A3B] focus-within:bg-white transition-all duration-300">
          <input type="text" value={inputText} onChange={e => setInputText(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleSubmit()}
            placeholder={placeholders[phIndex]}
            className="flex-1 bg-transparent px-3 py-2.5 text-[#1C1C1C] outline-none text-base placeholder:text-[#A0A0A0]" />

          {/* 麦克风按钮（仅 Chrome/Edge 显示） */}
          {speechSupported && (
            <button ref={micBtnRef}
              onPointerDown={pressStart}
              onPointerUp={pressEnd}
              onPointerMove={pressMove}
              onPointerLeave={pressEnd}
              onTouchStart={pressStart}
              onTouchEnd={pressEnd}
              onTouchMove={pressMove}
              onContextMenu={e => e.preventDefault()}
              className={`w-14 h-14 rounded-full flex items-center justify-center transition-all select-none touch-none
                ${isRecording
                  ? willCancel ? 'bg-red-500 scale-110' : 'bg-red-500 animate-pulse scale-110'
                  : 'bg-[#E8E4DF] hover:bg-[#D9D4CF] text-[#5C5C5C]'}`}
              aria-label="按住说话">
              <Mic className={`w-6 h-6 ${isRecording ? 'text-white' : ''}`} />
            </button>
          )}

          <button onClick={handleSubmit} disabled={isProcessing || !inputText.trim()}
            className="w-14 h-14 bg-[#ED6A3B] hover:bg-[#D45D2E] disabled:opacity-40 rounded-full text-white flex items-center justify-center transition-all shadow-lg shadow-[#ED6A3B]/20"
            aria-label="发送">
            <Send className="w-6 h-6" />
          </button>
        </div>
      </div>
    </main>
  );
}
