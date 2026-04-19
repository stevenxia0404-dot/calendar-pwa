'use client';

import { useState, useEffect, useCallback } from 'react';
import { Mic, Send, Calendar, ChevronLeft, ChevronRight, Download, Cloud, CloudOff, LogIn, LogOut, RefreshCw } from 'lucide-react';

// ==================== 配置 ====================

// Coze 配置
const COZE_CONFIG = {
  enabled: true,
  apiUrl: 'https://api.coze.cn/v1/workflow/run',
  workflowId: '7630428453997576244',
  token: 'REDACTED',
};

// API 配置
const API_CONFIG = {
  // 你的 Workers 地址，部署后替换
  baseUrl: process.env.NEXT_PUBLIC_API_URL || 'https://schedule-api.yourdomain.com',
};

// ==================== 工具函数 ====================

function formatLocalDate(date: Date): string {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

function extractTime(text: string) {
  let isPM = text.includes('下午') || text.includes('晚上');
  let hour = 9, minute = 0;
  let matched = false;

  let m = text.match(/(\d{1,2})\s*点(?:\s*(\d{1,2})\s*分?)?/);
  if (m) {
    hour = parseInt(m[1]);
    if (m[2]) minute = parseInt(m[2]);
    matched = true;
  } else {
    m = text.match(/(\d{1,2})\s*[:：]\s*(\d{2})/);
    if (m) {
      hour = parseInt(m[1]);
      minute = parseInt(m[2]);
      matched = true;
      isPM = false;
    }
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
  const today = new Date();
  today.setHours(0, 0, 0, 0);

  if (text.includes('今天')) {
    return new Date(today);
  }

  if (text.includes('明天')) {
    const d = new Date(today);
    d.setDate(d.getDate() + 1);
    return d;
  }

  if (text.includes('后天')) {
    const d = new Date(today);
    d.setDate(d.getDate() + 2);
    return d;
  }

  if (text.includes('大后天')) {
    const d = new Date(today);
    d.setDate(d.getDate() + 3);
    return d;
  }

  const daysLater = text.match(/(\d+)天后/);
  if (daysLater) {
    const d = new Date(today);
    d.setDate(d.getDate() + parseInt(daysLater[1]));
    return d;
  }

  const weekDays = ['一', '二', '三', '四', '五', '六', '日', '天'];
  const nextWeekMatch = text.match(/下周([一二三四五六日天])/);
  if (nextWeekMatch) {
    const targetDay = weekDays.indexOf(nextWeekMatch[1]) + 1;
    const currentDay = today.getDay();
    const currentDayAdjusted = currentDay === 0 ? 7 : currentDay;
    const daysToAdd = (7 - currentDayAdjusted) + targetDay;
    const d = new Date(today);
    d.setDate(d.getDate() + daysToAdd);
    return d;
  }

  const thisWeekMatch = text.match(/本周([一二三四五六日天])/);
  if (thisWeekMatch) {
    const targetDay = weekDays.indexOf(thisWeekMatch[1]) + 1;
    const currentDay = today.getDay();
    const currentDayAdjusted = currentDay === 0 ? 7 : currentDay;
    let daysToAdd = targetDay - currentDayAdjusted;
    if (daysToAdd < 0) daysToAdd += 7;
    const d = new Date(today);
    d.setDate(d.getDate() + daysToAdd);
    return d;
  }

  const nextMonthMatch = text.match(/下个月(\d{1,2})[号日]/);
  if (nextMonthMatch) {
    const d = new Date(today);
    d.setMonth(d.getMonth() + 1);
    d.setDate(parseInt(nextMonthMatch[1]));
    return d;
  }

  const dateMatch = text.match(/(\d{1,2})月(\d{1,2})[号日]/);
  if (dateMatch) {
    const month = parseInt(dateMatch[1]) - 1;
    const day = parseInt(dateMatch[2]);
    const d = new Date(today.getFullYear(), month, day);
    if (d < today) {
      d.setFullYear(d.getFullYear() + 1);
    }
    return d;
  }

  return null;
}

async function callCozeAPI(text: string): Promise<{date: string, time: string, title: string, confidence: number} | null> {
  if (!COZE_CONFIG.enabled || !COZE_CONFIG.workflowId || !COZE_CONFIG.token) {
    return null;
  }

  try {
    const response = await fetch(COZE_CONFIG.apiUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${COZE_CONFIG.token}`,
      },
      body: JSON.stringify({
        workflow_id: COZE_CONFIG.workflowId,
        parameters: {
          user_input: text,
          current_date: formatLocalDate(new Date()),
        },
      }),
    });

    if (!response.ok) {
      console.error('Coze API error:', response.status);
      return null;
    }

    const data = await response.json();
    const dataStr = data.data || '';

    if (!dataStr) {
      return null;
    }

    const dataObj = JSON.parse(dataStr);
    const output = dataObj.output || '';

    if (!output) {
      return null;
    }

    const parsed = JSON.parse(output);

    return {
      date: parsed.date,
      time: parsed.time,
      title: parsed.title,
      confidence: parsed.confidence || 0.8,
    };
  } catch (error) {
    console.error('Coze call failed:', error);
    return null;
  }
}

// ==================== API 函数 ====================

async function apiRequest(endpoint: string, options: RequestInit = {}, token?: string) {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...options.headers as Record<string, string>,
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const response = await fetch(`${API_CONFIG.baseUrl}${endpoint}`, {
    ...options,
    headers,
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: 'Unknown error' }));
    throw new Error(error.error || `HTTP ${response.status}`);
  }

  return response.json();
}

// ==================== 类型定义 ====================

interface ScheduleEvent {
  id: number;
  title: string;
  date: string;
  time: string;
  raw: string;
}

interface User {
  id: number;
  username: string;
  avatar_url: string;
}

// ==================== 主组件 ====================

export default function Home() {
  // 状态
  const [events, setEvents] = useState<ScheduleEvent[]>([]);
  const [currentDate, setCurrentDate] = useState(new Date());
  const [selectedDate, setSelectedDate] = useState(new Date());
  const [inputText, setInputText] = useState('');
  const [isProcessing, setIsProcessing] = useState(false);
  const [detailDate, setDetailDate] = useState<string | null>(null);
  const [isRecording, setIsRecording] = useState(false);
  const [editingEventId, setEditingEventId] = useState<number | null>(null);
  const [editForm, setEditForm] = useState({ title: '', date: '', time: '' });

  // 新增：用户状态
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [isOnline, setIsOnline] = useState(false);
  const [isSyncing, setIsSyncing] = useState(false);
  const [showLogin, setShowLogin] = useState(false);

  // ==================== 初始化 ====================

  // 1. 从 URL 获取 token（GitHub 登录回调）
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const urlToken = urlParams.get('token');

    if (urlToken) {
      localStorage.setItem('schedule_token', urlToken);
      setToken(urlToken);
      // 清除 URL 中的 token
      window.history.replaceState({}, '', window.location.pathname);
    } else {
      const savedToken = localStorage.getItem('schedule_token');
      if (savedToken) {
        setToken(savedToken);
      }
    }
  }, []);

  // 2. 加载本地数据
  useEffect(() => {
    const saved = localStorage.getItem('schedule_events');
    if (saved) {
      try {
        setEvents(JSON.parse(saved));
      } catch (e) {
        console.error(e);
      }
    }
  }, []);

  // 3. 保存到本地
  useEffect(() => {
    localStorage.setItem('schedule_events', JSON.stringify(events));
  }, [events]);

  // 4. 验证 token 并获取用户信息
  useEffect(() => {
    if (!token) {
      setUser(null);
      setIsOnline(false);
      return;
    }

    apiRequest('/auth/me', {}, token)
      .then(data => {
        setUser(data.user);
        setIsOnline(true);
        // 登录成功后同步云端数据
        syncFromCloud();
      })
      .catch(() => {
        // Token 无效
        localStorage.removeItem('schedule_token');
        setToken(null);
        setUser(null);
        setIsOnline(false);
      });
  }, [token]);

  // ==================== 同步功能 ====================

  // 从云端同步到本地
  const syncFromCloud = async () => {
    if (!token) return;

    setIsSyncing(true);
    try {
      const data = await apiRequest('/events', {}, token);
      const cloudEvents = data.events || [];

      // 合并策略：云端为准（因为可以跨设备同步）
      // 如果本地有数据且云端为空，上传本地数据
      if (cloudEvents.length === 0 && events.length > 0) {
        await uploadAllToCloud();
      } else {
        // 否则用云端数据
        setEvents(cloudEvents);
      }
    } catch (error) {
      console.error('Sync failed:', error);
    } finally {
      setIsSyncing(false);
    }
  };

  // 上传所有本地数据到云端
  const uploadAllToCloud = async () => {
    if (!token || events.length === 0) return;

    try {
      await apiRequest('/events/sync', {
        method: 'POST',
        body: JSON.stringify({ events }),
      }, token);
    } catch (error) {
      console.error('Upload failed:', error);
    }
  };

  // 单个事件同步到云端
  const syncEventToCloud = async (event: ScheduleEvent, method: 'POST' | 'PUT' | 'DELETE' = 'POST') => {
    if (!token) return;

    try {
      if (method === 'POST') {
        const { id, ...eventData } = event;
        await apiRequest('/events', {
          method: 'POST',
          body: JSON.stringify(eventData),
        }, token);
      } else if (method === 'PUT') {
        const { id, ...eventData } = event;
        await apiRequest(`/events/${id}`, {
          method: 'PUT',
          body: JSON.stringify(eventData),
        }, token);
      } else if (method === 'DELETE') {
        await apiRequest(`/events/${event.id}`, {
          method: 'DELETE',
        }, token);
      }
    } catch (error) {
      console.error('Sync event failed:', error);
    }
  };

  // ==================== 登录功能 ====================

  const handleLogin = async () => {
    try {
      const data = await apiRequest('/auth/github');
      if (data.url) {
        window.location.href = data.url;
      }
    } catch (error) {
      console.error('Login failed:', error);
      alert('登录失败，请重试');
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('schedule_token');
    setToken(null);
    setUser(null);
    setIsOnline(false);
  };

  // ==================== 日程操作 ====================

  const handleSubmit = useCallback(async () => {
    if (isProcessing || !inputText.trim()) return;
    setIsProcessing(true);

    const text = inputText.trim();
    let date: Date;
    let timeStr: string;
    let title: string;

    const smartDate = parseSmartDate(text);

    if (smartDate) {
      date = smartDate;
      const timeObj = extractTime(text);
      timeStr = timeObj.str;
      title = text.replace(/今天|明天|后天|大后天|下周|本周|\d{1,2}[号日]|(上午|下午|晚上|早上)?\s*\d{1,2}\s*[点:：]\s*\d{0,2}\s*[分]?|\d+天后/g, '').trim() || '新日程';
    } else if (COZE_CONFIG.enabled) {
      try {
        const cozeResult = await callCozeAPI(text);
        if (cozeResult) {
          date = new Date(cozeResult.date);
          timeStr = cozeResult.time;
          title = cozeResult.title;
        } else {
          date = new Date(selectedDate);
          const timeObj = extractTime(text);
          timeStr = timeObj.str;
          title = text || '新日程';
        }
      } catch {
        date = new Date(selectedDate);
        const timeObj = extractTime(text);
        timeStr = timeObj.str;
        title = text || '新日程';
      }
    } else {
      date = new Date(selectedDate);
      const timeObj = extractTime(text);
      timeStr = timeObj.str;
      title = text || '新日程';
    }

    const newEvent: ScheduleEvent = {
      id: Date.now(),
      title,
      date: formatLocalDate(date),
      time: timeStr,
      raw: text
    };

    setEvents(prev => [...prev, newEvent]);

    // 如果在线，同步到云端
    if (isOnline && token) {
      await syncEventToCloud(newEvent, 'POST');
    }

    setInputText('');
    setIsProcessing(false);
    setDetailDate(formatLocalDate(date));
  }, [inputText, isProcessing, selectedDate, isOnline, token]);

  const handleVoice = () => {
    setIsRecording(true);
    setInputText('（请说出日程，如：后天下午3点买菜）');
    setTimeout(() => setIsRecording(false), 2000);
  };

  const startEdit = (event: ScheduleEvent) => {
    setEditingEventId(event.id);
    setEditForm({
      title: event.title,
      date: event.date,
      time: event.time
    });
  };

  const saveEdit = async () => {
    if (!editingEventId) return;

    const updatedEvent = {
      id: editingEventId,
      title: editForm.title,
      date: editForm.date,
      time: editForm.time,
      raw: events.find(e => e.id === editingEventId)?.raw || ''
    };

    setEvents(prev => prev.map(e =>
      e.id === editingEventId
        ? updatedEvent
        : e
    ));

    // 如果在线，同步更新
    if (isOnline && token) {
      await syncEventToCloud(updatedEvent, 'PUT');
    }

    setEditingEventId(null);
    if (detailDate !== editForm.date) {
      setDetailDate(editForm.date);
    }
  };

  const cancelEdit = () => {
    setEditingEventId(null);
    setEditForm({ title: '', date: '', time: '' });
  };

  const deleteEvent = async (id: number) => {
    if (!confirm('确定要删除这个日程吗？')) return;

    const eventToDelete = events.find(e => e.id === id);
    setEvents(prev => prev.filter(e => e.id !== id));

    // 如果在线，同步删除
    if (isOnline && token && eventToDelete) {
      await syncEventToCloud(eventToDelete, 'DELETE');
    }
  };

  const handleExport = () => {
    const headers = ['日期', '时间', '事项', '原始输入'];
    const sortedEvents = [...events].sort((a, b) => a.date.localeCompare(b.date));
    const rows = sortedEvents.map(e => [e.date, e.time, e.title, e.raw]);

    const csvContent = [
      headers.join(','),
      ...rows.map(row => row.map(cell => `"${cell}"`).join(','))
    ].join('\n');

    const blob = new Blob(['\ufeff' + csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `日程表_${formatLocalDate(new Date())}.csv`;
    link.click();
  };

  // ==================== 日历渲染 ====================

  const renderCalendar = () => {
    const year = currentDate.getFullYear();
    const month = currentDate.getMonth();
    const firstDay = (new Date(year, month, 1).getDay() + 6) % 7;
    const daysInMonth = new Date(year, month + 1, 0).getDate();
    const daysInPrevMonth = new Date(year, month, 0).getDate();

    const days = [];

    for (let i = firstDay - 1; i >= 0; i--) {
      days.push(
        <div key={`prev-${i}`} className="text-gray-300 text-center py-2 text-sm">
          {daysInPrevMonth - i}
        </div>
      );
    }

    const today = new Date();
    for (let i = 1; i <= daysInMonth; i++) {
      const d = new Date(year, month, i);
      const dateStr = formatLocalDate(d);
      const hasEvent = events.some(e => e.date === dateStr);
      const isActive = formatLocalDate(selectedDate) === dateStr;
      const isToday = formatLocalDate(today) === dateStr;

      days.push(
        <button
          key={i}
          onClick={() => {
            setSelectedDate(d);
            setDetailDate(dateStr);
          }}
          aria-label={`${month + 1}月${i}日`}
          className={`
            relative py-2 text-sm rounded-xl transition-all duration-200
            ${isActive
              ? 'bg-indigo-500 text-white font-bold shadow-lg scale-105'
              : 'hover:bg-gray-50 text-gray-700'
            }
            ${isToday && !isActive ? 'border-2 border-indigo-400 text-indigo-600 font-bold bg-indigo-50' : ''}
          `}
        >
          {i}
          {hasEvent && (
            <span className={`
              absolute bottom-1 left-1/2 -translate-x-1/2 w-1.5 h-1.5 rounded-full
              ${isActive ? 'bg-white' : 'bg-red-400'}
            `} />
          )}
        </button>
      );
    }

    return days;
  };

  const dayEvents = detailDate
    ? events.filter(e => e.date === detailDate).sort((a, b) => a.time.localeCompare(b.time))
    : [];

  const weekDays = ['一', '二', '三', '四', '五', '六', '日'];

  // ==================== 渲染 ====================

  return (
    <main className="min-h-screen pb-40 bg-gradient-to-br from-indigo-600 via-purple-600 to-pink-500">
      {/* Header */}
      <header className="bg-white/95 backdrop-blur-md px-6 py-5 sticky top-0 z-50 shadow-sm border-b border-gray-100">
        <div className="flex justify-between items-center max-w-lg mx-auto">
          <div>
            <h1 className="text-xl font-bold text-gray-800 flex items-center gap-2">
              <Calendar className="w-6 h-6 text-indigo-500" />
              AI日程管家
            </h1>
            <p className="text-xs text-gray-500 mt-1 flex items-center gap-2">
              智能语音识别 · 本地存储 · CSV导出
              {isOnline ? (
                <span className="flex items-center gap-1 text-green-600">
                  <Cloud className="w-3 h-3" />
                  已登录
                </span>
              ) : (
                <span className="flex items-center gap-1 text-gray-400">
                  <CloudOff className="w-3 h-3" />
                  未登录
                </span>
              )}
            </p>
          </div>
          <div className="flex items-center gap-2">
            {/* 同步按钮 */}
            {isOnline && (
              <button
                onClick={syncFromCloud}
                disabled={isSyncing}
                className="p-2 bg-blue-100 rounded-full hover:bg-blue-200 transition-colors"
                aria-label="同步"
                title="同步云端数据"
              >
                <RefreshCw className={`w-5 h-5 text-blue-600 ${isSyncing ? 'animate-spin' : ''}`} />
              </button>
            )}
            {/* 登录/登出按钮 */}
            {user ? (
              <button
                onClick={handleLogout}
                className="p-2 bg-red-100 rounded-full hover:bg-red-200 transition-colors"
                aria-label="登出"
                title={`登出 (${user.username})`}
              >
                <LogOut className="w-5 h-5 text-red-600" />
              </button>
            ) : (
              <button
                onClick={handleLogin}
                className="p-2 bg-green-100 rounded-full hover:bg-green-200 transition-colors"
                aria-label="登录"
                title="GitHub 登录"
              >
                <LogIn className="w-5 h-5 text-green-600" />
              </button>
            )}
            {/* 导出按钮 */}
            <button
              onClick={handleExport}
              className="p-2 bg-gray-100 rounded-full hover:bg-gray-200 transition-colors"
              aria-label="导出日程表格"
            >
              <Download className="w-5 h-5 text-gray-600" />
            </button>
          </div>
        </div>
      </header>

      {/* 登录提示 */}
      {!user && showLogin && (
        <div className="mx-4 mt-4 bg-amber-50 border border-amber-200 rounded-xl p-4 flex items-start gap-3">
          <div className="flex-1">
            <p className="text-amber-800 text-sm">
              <strong>登录后可在多设备同步日程</strong><br />
              使用 GitHub 账号一键登录，数据自动同步到云端
            </p>
          </div>
          <button
            onClick={handleLogin}
            className="px-4 py-2 bg-amber-500 text-white text-sm rounded-lg hover:bg-amber-600 transition-colors"
          >
            登录
          </button>
          <button
            onClick={() => setShowLogin(false)}
            className="text-amber-400 hover:text-amber-600"
          >
            ×
          </button>
        </div>
      )}

      {/* 用户信息 */}
      {user && (
        <div className="mx-4 mt-4 bg-green-50 border border-green-200 rounded-xl px-4 py-2 flex items-center gap-3">
          {user.avatar_url && (
            <img src={user.avatar_url} alt={user.username} className="w-8 h-8 rounded-full" />
          )}
          <span className="text-green-800 text-sm">已登录：{user.username}</span>
        </div>
      )}

      {/* Detail Card */}
      {detailDate && (
        <div className="mx-4 mt-4 bg-white/95 backdrop-blur rounded-2xl p-5 shadow-xl border border-white/20 animate-in slide-in-from-top-2">
          <div className="flex justify-between items-center mb-4">
            <h2 className="font-bold text-gray-800 text-lg">{detailDate} 日程</h2>
            <button
              onClick={() => setDetailDate(null)}
              className="w-8 h-8 bg-gray-100 hover:bg-gray-200 rounded-full text-gray-500 flex items-center justify-center transition-colors"
              aria-label="关闭详情"
            >
              ×
            </button>
          </div>
          {dayEvents.length === 0 ? (
            <p className="text-gray-400 text-center py-8 text-sm">当日暂无日程，点击下方添加</p>
          ) : (
            <div className="space-y-3">
              {dayEvents.map(e => (
                <div key={e.id} className="p-3 bg-gray-50 rounded-xl border border-gray-100">
                  {editingEventId === e.id ? (
                    <div className="space-y-3">
                      <div>
                        <label className="text-xs text-gray-500 mb-1 block">事项</label>
                        <input
                          type="text"
                          value={editForm.title}
                          onChange={(ev) => setEditForm({ ...editForm, title: ev.target.value })}
                          className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm outline-none focus:border-indigo-400"
                        />
                      </div>
                      <div className="flex gap-3">
                        <div className="flex-1">
                          <label className="text-xs text-gray-500 mb-1 block">日期</label>
                          <input
                            type="date"
                            title="选择日期"
                            value={editForm.date}
                            onChange={(ev) => setEditForm({ ...editForm, date: ev.target.value })}
                            className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm outline-none focus:border-indigo-400"
                          />
                        </div>
                        <div className="flex-1">
                          <label className="text-xs text-gray-500 mb-1 block">时间</label>
                          <input
                            type="time"
                            title="选择时间"
                            value={editForm.time}
                            onChange={(ev) => setEditForm({ ...editForm, time: ev.target.value })}
                            className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm outline-none focus:border-indigo-400"
                          />
                        </div>
                      </div>
                      <div className="flex gap-2 justify-end">
                        <button
                          type="button"
                          onClick={cancelEdit}
                          className="px-4 py-1.5 text-sm text-gray-600 bg-gray-200 rounded-lg hover:bg-gray-300 transition-colors"
                        >
                          取消
                        </button>
                        <button
                          type="button"
                          onClick={saveEdit}
                          className="px-4 py-1.5 text-sm text-white bg-indigo-500 rounded-lg hover:bg-indigo-600 transition-colors"
                        >
                          保存
                        </button>
                      </div>
                    </div>
                  ) : (
                    <div className="flex items-center gap-3">
                      <span className="bg-indigo-500 text-white text-sm px-3 py-1.5 rounded-lg font-mono font-semibold min-w-[60px] text-center">
                        {e.time}
                      </span>
                      <div className="flex-1 min-w-0">
                        <div className="font-medium text-gray-800 truncate">{e.title}</div>
                        <div className="text-xs text-gray-400 mt-0.5 truncate">{e.raw}</div>
                      </div>
                      <div className="flex gap-1">
                        <button
                          type="button"
                          onClick={() => startEdit(e)}
                          className="p-2 text-gray-500 hover:text-indigo-500 hover:bg-indigo-50 rounded-lg transition-colors"
                          aria-label="编辑"
                        >
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                          </svg>
                        </button>
                        <button
                          type="button"
                          onClick={() => deleteEvent(e.id)}
                          className="p-2 text-gray-500 hover:text-red-500 hover:bg-red-50 rounded-lg transition-colors"
                          aria-label="删除"
                        >
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                          </svg>
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
      <div className="mx-4 mt-4 bg-white/95 backdrop-blur rounded-2xl p-5 shadow-xl border border-white/20">
        <div className="flex justify-between items-center mb-5">
          <h2 className="text-lg font-bold text-gray-800">
            {currentDate.getFullYear()}年{currentDate.getMonth() + 1}月
          </h2>
          <div className="flex gap-2">
            <button
              type="button"
              onClick={() => setCurrentDate(d => new Date(d.getFullYear(), d.getMonth() - 1))}
              className="w-9 h-9 bg-gray-100 hover:bg-gray-200 rounded-full text-gray-600 flex items-center justify-center transition-colors"
              aria-label="上个月"
            >
              <ChevronLeft className="w-5 h-5" />
            </button>
            <button
              type="button"
              onClick={() => setCurrentDate(d => new Date(d.getFullYear(), d.getMonth() + 1))}
              className="w-9 h-9 bg-gray-100 hover:bg-gray-200 rounded-full text-gray-600 flex items-center justify-center transition-colors"
              aria-label="下个月"
            >
              <ChevronRight className="w-5 h-5" />
            </button>
          </div>
        </div>

        <div className="grid grid-cols-7 gap-1 mb-3">
          {weekDays.map(d => (
            <div key={d} className="text-center text-xs text-gray-400 py-2 font-medium">
              {d}
            </div>
          ))}
        </div>

        <div className="grid grid-cols-7 gap-1">
          {renderCalendar()}
        </div>
      </div>

      {/* Input */}
      <div className="fixed bottom-0 left-0 right-0 bg-white/95 backdrop-blur-lg px-5 py-5 pb-8 shadow-[0_-10px_40px_rgba(0,0,0,0.15)] rounded-t-3xl border-t border-white/30 z-50">
        <div className="flex items-center gap-3 bg-gray-100/80 p-2 rounded-2xl border border-transparent focus-within:border-indigo-400 focus-within:bg-white transition-all duration-300 shadow-inner">
          <input
            type="text"
            value={inputText}
            onChange={(e) => setInputText(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleSubmit()}
            placeholder="输入：后天下午3点买菜"
            className="flex-1 bg-transparent px-4 py-3 text-gray-800 outline-none text-base placeholder:text-gray-400"
          />

          <button
            type="button"
            onClick={handleVoice}
            className={`
              w-11 h-11 rounded-full flex items-center justify-center transition-all
              ${isRecording
                ? 'bg-red-500 animate-pulse text-white'
                : 'bg-gray-200 hover:bg-gray-300 text-gray-600'
              }
            `}
            aria-label="语音输入"
          >
            <Mic className="w-5 h-5" />
          </button>

          <button
            type="button"
            onClick={handleSubmit}
            disabled={isProcessing || !inputText.trim()}
            className="w-11 h-11 bg-indigo-500 hover:bg-indigo-600 disabled:opacity-40 rounded-full text-white flex items-center justify-center transition-all shadow-lg shadow-indigo-200"
            aria-label="发送日程"
          >
            <Send className="w-5 h-5" />
          </button>
        </div>

        {isRecording && (
          <div className="text-center mt-2 text-sm text-red-500 animate-pulse">
            🎤 请说话...
          </div>
        )}
      </div>
    </main>
  );
}
