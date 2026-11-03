'use client';

import { useState, useEffect, useRef } from 'react';
import { RefreshCw, Upload } from 'lucide-react';
import {
  enqueueOp, removeOp, pendingIds, readQueue, writeQueue, clearQueue, reconcile,
} from '@/lib/syncQueue';
import type { SyncOp, SyncPayload, CloudItem } from '@/lib/syncQueue';
import {
  filterByRange, toExportRow, toMatrix, toCsv, toText, exportFileName,
} from '@/lib/exportLib';
import type { ExportRange } from '@/lib/exportLib';
import { buildXlsx } from '@/lib/xlsxWriter';
import { parseImportRows, looksLikeHeader, mapColumns, xlsxRowToTemplateCells, cellToText } from '@/lib/importParser';
import { toCsvLine } from '@/lib/csv';
import { newId } from '@/lib/id';


import MonthView from '@/components/MonthView';
import DayCard from '@/components/DayCard';
import StatCard from '@/components/StatCard';
import SettingsCard from '@/components/SettingsCard';
import InputArea from '@/components/InputArea';
import { useDialog, DialogHost } from '@/components/Dialog';
import Inspector from '@/components/Inspector';
import { ParsedResult } from '@/lib/dateParser';
import type { ScheduleEvent } from '@/lib/scheduleTypes';

// ==================== 配置 ====================

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'https://schedule-api.boluomate.com';

// 导入文件大小上限。课表正常在几百 KB 以内，5MB 足够，
// 同时能挡住构造出来的超大文件把浏览器内存拖垮。
const MAX_IMPORT_FILE_BYTES = 5 * 1024 * 1024;

// 导入行数上限。
// 只限文件大小不够 —— 5MB 的 xlsx 可能有几万行，
// 逐行解析再加上预览渲染，足以把手机浏览器卡死。
// 一个学期的课表通常几百行，5000 行留了充足余量。
const MAX_IMPORT_ROWS = 5000;

// ==================== 工具函数 ====================

function formatLocalDate(date: Date): string {
  const y = date.getFullYear();
  const m = String(date.getMonth() + 1).padStart(2, '0');
  const d = String(date.getDate()).padStart(2, '0');
  return `${y}-${m}-${d}`;
}

// 单元格值转文本已移到 src/lib/importParser.ts ——
// 它跟导入解析是一套规则，放一起才能被单测覆盖。

// ==================== API 函数 ====================

// 请求选项：在标准 RequestInit 上加一个超时。
// fetch 默认永不超时，服务端 hang 住时缓存队列会一直卡在第一条上，
// 用户看到的是「离线待同步」，实际是请求挂死。
type ApiOptions = RequestInit & { timeout?: number };

const DEFAULT_API_TIMEOUT = 15000;

function makeApiError(message: string, status: number) {
  const err = new Error(message) as Error & { status?: number };
  err.status = status;
  return err;
}

// 各端点的响应结构。写清楚是为了让调用点拿到真正的类型，
// 而不是一堆 unknown 断言 —— 断言写多了，等于没类型。
interface ResMe { user: User }
interface ResSendCode { code_sent?: boolean; error?: string }
interface ResVerify { token: string; user: User }
interface ResEvents { events: CloudEvent[]; server_time?: number }
interface ResWrite { id?: string; ok?: boolean; updated_at?: number; deleted_at?: number }
interface ResCalToken { cal_token?: string }

async function api<T = Record<string, unknown>>(
  path: string,
  options: ApiOptions = {},
  token?: string | null,
): Promise<T> {
  const { timeout = DEFAULT_API_TIMEOUT, ...init } = options;
  const headers: Record<string, string> = { 'Content-Type': 'application/json', ...init.headers as Record<string, string> };
  if (token) headers['Authorization'] = `Bearer ${token}`;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  try {
    const res = await fetch(`${API_BASE}${path}`, { ...init, headers, signal: controller.signal });

    // 先读文本再解析：网关错误（Cloudflare 502/504）返回的是 HTML，
    // 直接 res.json() 会抛 "Unexpected token <"，既误导用户，
    // 也让上层把「网关错误」误判成「网络不通」。
    const text = await res.text();
    let data: Record<string, unknown> = {};
    if (text) {
      try {
        data = JSON.parse(text) as Record<string, unknown>;
      } catch {
        throw makeApiError(
          res.ok ? '服务器返回了无法识别的数据' : `服务暂时不可用（HTTP ${res.status}）`,
          res.status,
        );
      }
    }

    if (!res.ok) {
      const msg = typeof data.error === 'string' ? data.error : `HTTP ${res.status}`;
      throw makeApiError(msg, res.status);
    }
    return data as T;
  } catch (e) {
    // AbortController 触发的中断转成可读的错误，并把 status 标成 0，
    // 让上层能与「服务端明确拒绝」区分开（前者该重试，后者不该）。
    if ((e as Error).name === 'AbortError') {
      throw makeApiError('请求超时，请检查网络', 0);
    }
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

// ==================== 类型 ====================

interface User { id: number; email: string; role?: 'family' | 'user'; }

/** 服务端返回的原始记录形态（下划线命名，与库里字段一致） */
interface CloudEvent {
  id: string;
  title: string;
  date: string;
  time?: string;
  end_time?: string;
  location?: string;
  people?: string;
  raw?: string;
  type?: string;
  completed?: number;
  date_confirmed?: number;
  deleted_at?: number;
  updated_at: number;
}

// ==================== 主组件 ====================

export default function Home() {
  // 日程状态
  const [events, setEvents] = useState<ScheduleEvent[]>([]);
  const [detailDate, setDetailDate] = useState<string | null>(null);
  const [editingEventId, setEditingEventId] = useState<string | null>(null);
  const [editForm, setEditForm] = useState({ title: '', date: '', time: '', endTime: '', endDate: '', projectId: '', location: '', people: '' });

  // v4.1：月历锚点（当前显示哪个月）与窄屏判定
  const [monthAnchor, setMonthAnchor] = useState(new Date());
  const [isNarrow, setIsNarrow] = useState(false);

  // v4.1：三个浮层
  //   showDayCard  点日历某天 → 那天的明细卡片
  //   showStatCard 点四宫格某格 → 该类别的清单卡片
  //   showSettings 点设置齿轮 → 设置卡片
  // 下面全部模糊（行为层实现），输入框永远在最上层。
  const [showDayCard, setShowDayCard] = useState(false);
  const [showStatCard, setShowStatCard] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  /** 四宫格点的是哪一类 */
  const [statKind, setStatKind] = useState<'event' | 'task' | 'project' | 'completed'>('event');

  // 应用内弹窗 —— 替代原生 confirm()/alert()
  // （iOS PWA 里原生 confirm 会被静默忽略，返回 undefined，
  //   于是「删除」点了跟没点一样，什么提示都没有）
  const { dialog, ask, tell, close } = useDialog();
  /** 在四宫格卡里点了「＋」—— 下面输入框加的内容归到那一类 */
  const [statAdding, setStatAdding] = useState(false);

  // 认证状态
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(null);
  // 同步状态三态（文档 11.6）：
  //   syncing 正在重放队列或拉取
  //   synced  队列空且上次拉取成功
  //   offline 队列非空但网络不可用
  const [syncState, setSyncState] = useState<'syncing' | 'synced' | 'offline'>('synced');
  const [pendingCount, setPendingCount] = useState(0);

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
  // 导出：范围与格式
  const [showExportModal, setShowExportModal] = useState(false);
  const [exportRange, setExportRange] = useState<ExportRange>('week');
  const [exportFormat, setExportFormat] = useState<'text' | 'csv' | 'xlsx'>('text');
  const [exportFrom, setExportFrom] = useState(formatLocalDate(new Date()));
  const [exportTo, setExportTo] = useState(formatLocalDate(new Date()));
  const [importText, setImportText] = useState('');
  const [importPreview, setImportPreview] = useState<ScheduleEvent[] | null>(null);
  const [importGroups, setImportGroups] = useState<{ id: string; name: string; count: number; time: string }[]>([]);

  const submitFeedback = async () => {
    if (!feedbackText.trim()) return;
    try {
      await api<ResWrite>('/feedback', { method: 'POST', body: JSON.stringify({ text: feedbackText, email: user?.email || '' }) }, token);
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

  // 「已从 localStorage 读完」标志。
  //
  // 为什么必须有它：读（effect#1）和写（effect#2）是两个 effect，
  // 而 setEvents 是**异步**的 —— effect#2 第一次跑的时候 events 还是初始的 []，
  // 于是「刚读出来的数据」被「空数组」覆盖掉了。
  // 生产环境侥幸没事（第二次渲染会写回正确值），
  // 但 StrictMode 下 effect 跑两次 —— 数据直接没了。
  //
  // 标志位保证：初始化完成之前不写，读到的东西不会被覆盖。
  const [hydrated, setHydrated] = useState(false);

  useEffect(() => {
    const saved = localStorage.getItem('schedule_events');
    if (saved) { try { setEvents(JSON.parse(saved)); } catch { /* ignore */ } }

    const savedToken = localStorage.getItem('schedule_token');
    if (savedToken) setToken(savedToken);

    const savedGroups = localStorage.getItem('schedule_import_groups');
    if (savedGroups) { try { setImportGroups(JSON.parse(savedGroups)); } catch { /* ignore */ } }

    setHydrated(true);
  }, []);

  useEffect(() => {
    // 没读完之前不写 —— 否则空数组会把刚读出来的数据冲掉
    if (!hydrated) return;
    localStorage.setItem('schedule_events', JSON.stringify(events));
  }, [events, hydrated]);

  // 自动验证 token
  useEffect(() => {
    if (!token) { setUser(null); return; }
    api<ResMe>('/auth/me', {}, token)
      .then(d => setUser(d.user))
      .catch(() => { localStorage.removeItem('schedule_token'); setToken(null); setUser(null); });
  }, [token]);

  // ==================== 同步 ====================
  //
  // v4.0 的同步是「服务端权威 + 本地操作队列」（文档第十一章）。
  //
  // v3 的问题很具体：写操作直接发、失败静默，同步只拉不推。
  // 于是「一次失败上传」= 那条日程永远只在本机，其他设备看不到，
  // 用户零感知；「删除」因为云端已物理消失，对端拉不到，也就删不掉。
  // 这三条造成的是数据静默丢失，不是功能不可用。
  //
  // v4.0：所有写操作先进队列再按序重放；删除走服务端墓碑；
  // 时间戳一律服务端生成，客户端时钟不作数。

  // 同步游标按用户分开 —— 换账号时不能沿用上一个账号的游标，
  // 否则会用错的起点做增量，拉不全新账号的数据。
  const syncKeyRef = useRef('schedule_last_sync_anon');
  useEffect(() => {
    syncKeyRef.current = `schedule_last_sync_${user?.id ?? 'anon'}`;
  }, [user?.id]);

  // 轮询回调捕获的是当时的 events 与 user，会过期。
  // 用 ref 拿最新值，避免「本地有未上传的记录却没被补传」。
  const eventsRef = useRef<ScheduleEvent[]>([]);
  useEffect(() => { eventsRef.current = events; }, [events]);

  // 把一条记录转成上传用的内容。
  // 不含 id 之外的元信息 —— 时间戳由服务端生成，客户端传了也会被忽略。
  const toPayload = (e: ScheduleEvent): SyncPayload => ({
    title: e.title,
    date: e.date,
    time: e.time,
    endTime: e.endTime,
    endDate: e.endDate || '',
    projectId: e.projectId || '',
    location: e.location,
    people: e.people,
    raw: e.raw,
    type: e.type,
    completed: e.completed,
    dateConfirmed: e.dateConfirmed ?? 1,
  });

  // 按序重放队列。成功一条删一条；失败就停下，剩下的留着等下次。
  // 每条操作都是幂等的，重放两次结果一样 —— 这是队列能安全重试的前提。
  const flushQueue = async (): Promise<boolean> => {
    if (!token) return false;

    // 服务端时间戳先攒着，整个队列跑完再一次性回写。
    // 之前是每条都 setEvents(map)，队列 50 条就是 50 次全量重渲染 ——
    // 同步本该是后台动作，不该让界面卡成这样。
    const tsUpdates = new Map<string, number>();

    const applyTimestamps = () => {
      if (!tsUpdates.size) return;
      setEvents(prev => prev.map(e => {
        const ts = tsUpdates.get(e.id);
        return ts === undefined ? e : { ...e, updatedAt: ts, synced: true };
      }));
      tsUpdates.clear();
    };

    for (;;) {
      const q = readQueue();
      if (!q.length) { applyTimestamps(); setPendingCount(0); return true; }
      const item = q[0];

      try {
        let serverTs = 0;

        if (item.op === 'delete') {
          try {
            const r = await api<ResWrite>(`/events/${item.id}`, { method: 'DELETE' }, token);
            serverTs = r.updated_at || 0;
          } catch (e) {
            // 服务端本来就没有这条 → 视为已删除，别把队列卡住
            if ((e as { status?: number }).status !== 404) throw e;
          }
        } else if (item.op === 'create') {
          const r = await api<ResWrite>('/events', {
            method: 'POST',
            body: JSON.stringify({ id: item.id, ...item.payload }),
          }, token);
          serverTs = r.updated_at || 0;
        } else {
          try {
            const r = await api<ResWrite>(`/events/${item.id}`, {
              method: 'PUT',
              body: JSON.stringify(item.payload),
            }, token);
            serverTs = r.updated_at || 0;
          } catch (e) {
            // 服务端没有这条（旧数据，或别处删过）→ 退回创建
            if ((e as { status?: number }).status === 404) {
              const r = await api<ResWrite>('/events', {
                method: 'POST',
                body: JSON.stringify({ id: item.id, ...item.payload }),
              }, token);
              serverTs = r.updated_at || 0;
            } else throw e;
          }
        }

        // 服务端时间回写本地。
        // 本地时间戳若比服务端大，下次拉取会把这版判成「本地更新」，
        // 于是服务端的版本永远拉不下来 —— 所以必须以服务端为准。
        if (serverTs) tsUpdates.set(item.id, serverTs);

        writeQueue(removeOp(readQueue(), item.id));
        setPendingCount(readQueue().length);
      } catch (e) {
        const status = (e as { status?: number }).status ?? 0;

        // 关键区分：队列必须能「消化」一条永久失败的操作，
        // 否则它会永远卡在队首，后面的操作全部跟着推不上去 ——
        // 用户以为在同步，实际从那一刻起一条都没成功。
        //
        //   4xx（400/403/422…）→ 这条数据本身有问题，重试一万次也一样。
        //                        丢弃它，继续下一条。
        //   401              → 登录态问题，不是数据问题。留着等重新登录。
        //   0 / 5xx          → 网络或服务端临时故障。留着等下次重试。
        const permanent = status >= 400 && status < 500 && status !== 401;

        if (permanent) {
          console.warn('丢弃无法同步的操作（服务端拒绝）:', item.id, item.op, status);
          writeQueue(removeOp(readQueue(), item.id));
          setPendingCount(readQueue().length);
          continue;
        }

        // 网络不通或服务端出错：已成功的那些时间戳仍要落盘，
        // 否则它们会被当成「没同步过」，下次重新入队再传一遍。
        applyTimestamps();
        setSyncState('offline');
        setPendingCount(readQueue().length);
        return false;
      }
    }
  };

  // 把一条变更放进队列，然后立刻尝试推送。
  // 没登录时不入队 —— 队列属于某个账号。
  const enqueueChange = (op: SyncOp) => {
    const q = enqueueOp(readQueue(), op);
    writeQueue(q);
    setPendingCount(q.length);
    if (token) void flushQueue();
  };

  const syncFromCloud = async (since?: string) => {
    if (!token) return false;
    setSyncState('syncing');
    try {
      // 本地还没同步过的记录补传上去。
      // 没登录时记的东西不能因为登录而消失，也不能永远躺在本机。
      const unsynced = eventsRef.current.filter(e => e.synced !== true);
      if (unsynced.length) {
        let q = readQueue();
        for (const e of unsynced) {
          q = enqueueOp(q, {
            id: e.id, op: 'create', payload: toPayload(e), ts: e.updatedAt || Date.now(),
          });
        }
        writeQueue(q);
        setPendingCount(q.length);
      }

      // 先推后拉：本地还没上传的变更优先。
      // 反过来的话，拉回来的旧数据会把刚写的东西盖掉。
      if (!(await flushQueue())) return false;

      const qs = since ? `?since=${encodeURIComponent(since)}` : '';
      const { events: cloudEvents, server_time } = await api<ResEvents>(`/events${qs}`, {}, token);

      const items: CloudItem<ScheduleEvent>[] = (cloudEvents || []).map((ce: {
        id: string; updated_at: number; deleted_at?: number; title: string; date: string;
        time?: string; end_time?: string; end_date?: string; project_id?: string; location?: string; people?: string; raw?: string;
        type?: string; completed?: number; date_confirmed?: number;
      }) => ({
        id: ce.id,
        updatedAt: ce.updated_at,
        deleted: !!ce.deleted_at,
        value: ce.deleted_at ? null : {
          id: ce.id,
          title: ce.title,
          date: ce.date,
          time: ce.time || '',
          endTime: ce.end_time || '',
          endDate: ce.end_date || '',
          projectId: ce.project_id || '',
          location: ce.location || '',
          people: ce.people || '',
          raw: ce.raw || '',
          type: (ce.type || 'event') as 'event' | 'task' | 'project',
          completed: !!ce.completed,
          dateConfirmed: (ce.date_confirmed ?? 1) as 0 | 1,
          updatedAt: ce.updated_at,
          synced: true,
        },
      }));

      // 全量拉取才做删除对账；增量只管「变了的」。
      setEvents(prev => reconcile(prev, items, pendingIds(readQueue()), !since));

      localStorage.setItem(syncKeyRef.current, String(server_time || Date.now()));
      setSyncState('synced');
      return true;
    } catch {
      // 拉不到就是离线待同步。顶栏那个点的意义是「我记的东西不会丢」，
      // 所以离线必须让人看得见，不能继续静默失败。
      setSyncState('offline');
      return false;
    }
  };

  // 登录后自动同步（首次全量，之后按游标增量）
  useEffect(() => {
    if (!isOnline) return;
    const since = localStorage.getItem(syncKeyRef.current);
    void syncFromCloud(since || undefined);
  }, [isOnline]);

  // 30 秒增量轮询
  useEffect(() => {
    if (!isOnline) return;
    const timer = setInterval(() => {
      const since = localStorage.getItem(syncKeyRef.current);
      void syncFromCloud(since || undefined);
    }, 30000);
    return () => clearInterval(timer);
  }, [isOnline]);

  // 每 10 分钟一次全量拉取 —— 做删除对账，
  // 兜住「设备太久没上线，墓碑已被服务端回收」的情况
  useEffect(() => {
    if (!isOnline) return;
    const timer = setInterval(() => {
      void syncFromCloud(undefined);
    }, 10 * 60 * 1000);
    return () => clearInterval(timer);
  }, [isOnline]);

  // 网络恢复立刻补传
  useEffect(() => {
    if (!isOnline) return;
    const onOnline = () => {
      const since = localStorage.getItem(syncKeyRef.current);
      void syncFromCloud(since || undefined);
    };
    window.addEventListener('online', onOnline);
    return () => window.removeEventListener('online', onOnline);
  }, [isOnline]);

  // ==================== 认证操作 ====================

  const handleSendCode = async () => {
    if (!activateEmail || activateLoading) return;
    setActivateLoading(true); setActivateError('');
    try {
      const data = await api<ResSendCode>('/auth/send-code', { method: 'POST', body: JSON.stringify({ email: activateEmail }) });
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
      const data = await api<ResVerify>('/auth/verify', { method: 'POST', body: JSON.stringify({ email: activateEmail, code: activateCode }) });
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
    // 队列属于这个账号 —— 登出时清掉，
    // 别把上一个账号的待推变更推到下一个账号去
    clearQueue();
    setPendingCount(0);
    setToken(null); setUser(null);
  };



  const [icalUrl, setIcalUrl] = useState('');
  const [calError, setCalError] = useState('');

  const handleShowCalModal = async () => {
    setShowCalModal(true);
    setCalError('');
    if (!token) { setCalError('请先激活同步'); return; }
    try {
      const data = await api<ResCalToken>('/auth/cal-token', {}, token);
      setIcalUrl(`webcal://schedule-api.boluomate.com/events/ical?token=${encodeURIComponent(String(data.cal_token || ''))}`);
    } catch (e) {
      // 静默失败会让弹窗里出现一个空二维码，用户完全不知道发生了什么
      setIcalUrl('');
      setCalError((e as Error).message || '获取订阅链接失败，请稍后重试');
    }
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
  //
  // 关键：**去哪儿**由「当前编辑目标」决定。
  //   开了日期详情卡 → 加到那天
  //   开了任务/项目卡 → 加到那一类（无日期的记今天）
  //   都没开 → 照常按解析出来的日期落
  // 输入框在任何时候都显示、都在最上层 —— 它是「当前编辑目标」的输入框。
  const handleParsed = (parsed: ParsedResult) => {
    // 当前编辑目标决定日期与类型
    let targetDate = parsed.date;
    let targetType: ScheduleEvent['type'] = parsed.time ? 'event' : 'task';

    if (statAdding) {
      // 任务卡里加一条 —— 类型由卡片决定，日期没解析出来就落今天
      targetType = 'task';
      if (!targetDate) targetDate = formatLocalDate(new Date());
      setStatAdding(false);
    } else if (showDayCard && detailDate) {
      // 日期详情卡里加一条 —— 强制落到那天
      targetDate = detailDate;
    }

    const ev: ScheduleEvent = {
      id: newId(),
      title: parsed.title || parsed.raw,
      date: targetDate,
      time: parsed.time,
      endTime: '',
      // 跨日：从哪一天到哪一天。日期详情卡里加的那条强制落当天，不跨日。
      endDate: (showDayCard && detailDate) ? '' : (parsed.endDate || ''),
      location: '',
      people: '',
      raw: parsed.raw,
      updatedAt: Date.now(),
      type: targetType,
      completed: false,
      dateConfirmed: parsed.dateConfirmed,
    };
    setEvents(prev => [...prev, ev]);
    if (isOnline && token) {
      enqueueChange({ id: ev.id, op: 'create', payload: toPayload(ev), ts: Date.now() });
    }
    setDetailDate(ev.date);
  };

  // ==================== 项目操作 ====================
  //
  // 项目实体就是一条 type='project' 的记录：
  //   title = 项目名 · raw = 项目简介 · date = 创建日（月历不显示它）
  // 事件通过 projectId 指向它 —— 一个日程可以既在月历上、又属于某个项目。

  const createProject = (name: string) => {
    const p: ScheduleEvent = {
      id: newId(),
      title: name.trim(),
      date: formatLocalDate(new Date()),
      time: '',
      endTime: '',
      endDate: '',
      projectId: '',
      location: '',
      people: '',
      raw: '',
      updatedAt: Date.now(),
      type: 'project',
      completed: false,
      dateConfirmed: 1,
    };
    setEvents(prev => [...prev, p]);
    if (isOnline && token) {
      enqueueChange({ id: p.id, op: 'create', payload: toPayload(p), ts: p.updatedAt });
    }
  };

  /** 改项目名或简介 —— 改的是同一条记录的两个字段 */
  const patchProject = (id: string, patch: { title?: string; raw?: string }) => {
    const existing = events.find(e => e.id === id);
    if (!existing) return;
    const updated: ScheduleEvent = { ...existing, ...patch, updatedAt: Date.now() };
    setEvents(prev => prev.map(e => e.id === id ? updated : e));
    if (isOnline && token) {
      enqueueChange({
        id: updated.id,
        op: existing.synced ? 'update' : 'create',
        payload: toPayload(updated),
        ts: updated.updatedAt,
      });
    }
  };

  /**
   * 删项目。
   *
   * 它下面的事**不删** —— 全部归为「完成」。
   * 理由：删的是容器，不是那些事本身；把它们标成完成，
   * 既不丢数据，又不会让它们继续占着月历上未完成的位置。
   */
  const deleteProject = async (id: string) => {
    const proj = events.find(e => e.id === id);
    const affected = events.filter(e => e.projectId === id);
    const ok = await ask(
      `删掉项目「${proj?.title || ''}」？`,
      affected.length
        ? `它下面的 ${affected.length} 件事不会被删，会归到「完成」里。`
        : '这个项目下面还没有事。',
      { danger: true, confirmText: '删掉项目' },
    );
    if (!ok) return;
    const ts = Date.now();
    setEvents(prev => prev
      .filter(e => e.id !== id)
      .map(e => (e.projectId === id ? { ...e, completed: true, updatedAt: ts } : e)));
    if (isOnline && token) {
      enqueueChange({ id, op: 'delete', ts });
      for (const e of affected) {
        enqueueChange({
          id: e.id,
          op: e.synced ? 'update' : 'create',
          payload: toPayload({ ...e, completed: true, updatedAt: ts }),
          ts,
        });
      }
    }
  };

  // ==================== 日程操作 ====================

  const startEdit = (event: ScheduleEvent) => {
    setEditingEventId(event.id);
    setEditForm({ title: event.title, date: event.date, time: event.time, endTime: event.endTime, endDate: event.endDate || '', projectId: event.projectId || '', location: event.location, people: event.people });
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
      endDate: editForm.endDate,
      projectId: editForm.projectId,
      location: editForm.location,
      people: editForm.people,
      raw: existing?.raw || '',
      updatedAt: Date.now(),
      type: existing?.type || 'event',
      completed: existing?.completed || false,
      // 用户手动改过日期就算确认了，「待确认」标记该消失
      dateConfirmed: editForm.date !== existing?.date ? 1 : (existing?.dateConfirmed ?? 1),
    };

    setEvents(prev => prev.map(e => e.id === editingEventId ? updated : e));
    if (isOnline && token) {
      enqueueChange({
        id: updated.id,
        // 没同步过的记录要走创建，不能走更新（服务端还不认识它）
        op: existing?.synced ? 'update' : 'create',
        payload: toPayload(updated),
        ts: Date.now(),
      });
    }

    setEditingEventId(null);
    if (detailDate !== editForm.date) setDetailDate(editForm.date);
  };

  // 删除。同步是「入队 + 后台重放」，所以这里不需要 await ——
  // 界面立刻把这条移走，推送成功与否交给队列处理。
  const deleteEvent = async (id: string) => {
    if (!await ask('确定要删除这个日程吗？', '', { danger: true, confirmText: '删掉' })) return;
    // 删的是项目容器 → 它下面的事归为「完成」，别留成孤儿
    const isProject = events.find(e => e.id === id)?.type === 'project';
    if (isProject) {
      await deleteProject(id);
      return;
    }
    setEvents(prev => prev.filter(e => e.id !== id));
    if (isOnline && token) {
      // 墓碑语义：服务端会留一条删除标记，同步给其它设备，
      // 它们收到后本地也删 —— 这样删除才能跨设备传播。
      enqueueChange({ id, op: 'delete', ts: Date.now() });
    }
  };

  const toggleTaskCompleted = (id: string) => {
    const ev = events.find(e => e.id === id);
    if (!ev) return;
    const next = { ...ev, completed: !ev.completed, updatedAt: Date.now() };
    setEvents(prev => prev.map(e => e.id === id ? next : e));
    if (isOnline && token) {
      // 走通用更新而不是「服务端翻转」的接口 ——
      // 翻转型接口重放两次会互相抵消，而队列重放必须幂等。
      enqueueChange({
        id,
        op: ev.synced ? 'update' : 'create',
        payload: toPayload(next),
        ts: Date.now(),
      });
    }
  };

  // ==================== 导出 ====================
  //
  // 导出只有一个用途：把一段时间里的事拿出来，自己去写周报或交差。
  // 所以三档格式内容完全一致，只是拿去用的地方不同。

  const exportRows = () => filterByRange(
    // 项目不是「这段时间里的事」，是容器 —— 不进导出
    events.filter(e => e.type !== 'project').map(toExportRow),
    exportRange,
    new Date(),
    { from: exportFrom, to: exportTo },
  );

  const downloadBlob = (blob: Blob, filename: string) => {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    // 不立刻 revoke —— 立刻撤销会让部分浏览器下载失败
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  };

  const doExport = () => {
    const rows = exportRows();
    const name = exportFileName(exportRange, '', new Date());

    if (exportFormat === 'text') {
      downloadBlob(new Blob([toText(rows)], { type: 'text/plain;charset=utf-8;' }), `${name}.txt`);
    } else if (exportFormat === 'csv') {
      downloadBlob(new Blob([toCsv(rows)], { type: 'text/csv;charset=utf-8;' }), `${name}.csv`);
    } else {
      const bytes = buildXlsx(toMatrix(rows));
      downloadBlob(
        new Blob([new Uint8Array(bytes)], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' }),
        `${name}.xlsx`,
      );
    }
    setShowExportModal(false);
  };

  const generateCsvTemplate = () => {
    const sample = [
      // 末列「结束日期」是跨日用的：填了就占这几天，月历上连成一条
      '日期,开始时间,结束时间,事项,地点,人员,备注,结束日期',
      '2026-07-20,08:50,10:30,初始训练-模拟航班,青浦B777经济静态舱,张教员,,',
      '2026-07-21,12:50,13:50,团队周会,C楼201,全组,,',
      '2026-07-22,,,整理文档,,,培训材料归档,,',
      '2026-07-23,09:00,,跨日培训,C楼201,张教员,,2026-07-25',
    ].join('\n');
    const blob = new Blob(['﻿' + sample], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = 'schedule_template.csv'; a.click();
    // 与 downloadBlob 同样的处理：不能立刻 revoke，否则部分浏览器下载中断
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  };

  const parseImportFile = async (file: File) => {
    try {
      const ext = file.name.split('.').pop()?.toLowerCase();

      if (file.size > MAX_IMPORT_FILE_BYTES) {
        await tell('文件太大', `${(file.size / 1024 / 1024).toFixed(1)}MB —— 请拆分后再导入`);
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

        // 表头识别：先找完全相等的，再找包含的。
        // 「包含」这一层必须带占用标记 —— 否则「结束时间」会被
        // 「时间」这一列先抢走（因为它也包含「时间」）。
        // 列映射与表头识别交给 importParser —— 与粘贴文本那条路共用一套规则
        const headerCells = header ? header.map(c => cellToText(c).trim()) : [];
        const hasHeader = headerCells.length > 0 && looksLikeHeader(headerCells.join(','));
        const idx = hasHeader ? mapColumns(headerCells) : {
          date: 0, time: 1, endTime: 2, content: 3, location: 4, people: 5, note: 6,
          endDate: -1,
        };

        // 八列：前七列位置不动，跨日的「结束日期」放末尾
        const csvLines = ['日期,开始时间,结束时间,事项,地点,人员,备注,结束日期'];
        let rowCount = 0;
        for (const r of dataRows) {
          if (++rowCount > MAX_IMPORT_ROWS) {
            await tell('数据太多', `超过 ${MAX_IMPORT_ROWS} 行 —— 请拆成几个文件分别导入`);
            return;
          }
          // 日期列和时间列由 cellToParts 处理 —— Excel 的「纯时间」单元格
          // 和日期单元格都是 Date 对象，按文本拍平会把时间整个丢掉
          // （8:50 → "1899-12-30" → 时间列空着，记录被当成没时间的）。
          const cells = xlsxRowToTemplateCells(r, idx);
          // 没有日期也没有事项 → 这行没什么可导的，跳过
          if (!cells[0] && !cells[3]) continue;
          csvLines.push(toCsvLine(cells));
        }
        setImportText(csvLines.join('\n'));
      } else if (ext === 'xls') {
        // 老版 .xls 是二进制格式，按文本读只会得到乱码，
        // 用户看到的是「未识别到有效数据」，根本不知道该怎么办。
        // 明确告诉他怎么转，比给个哑巴失败好。
        await tell('暂不支持老版 .xls', '请用 Excel 打开后「另存为」.xlsx 再导入。');
        return;
      } else {
        // 纯文本类（txt / ics / json 等）按文本读，交给下面的规则解析。
        // 注意：这里不是 AI 解析 —— v4.0 已移除 AI 链路，
        // 所有导入都走 importParser 的确定性规则。
        setImportText(await file.text());
      }
    } catch { await tell('文件读取失败', '换个文件试试，或者先把文件转成 xlsx / csv。'); }
  };

  const parseImportText = async () => {
    // 行数先挡一道：文本解析同样吃内存，几万行的 CSV 一样能卡死页面
    const lineCount = importText.split('\n').length;
    if (lineCount > MAX_IMPORT_ROWS + 10) {
      await tell('数据太多', `约 ${lineCount} 行，上限 ${MAX_IMPORT_ROWS} 行 —— 请拆成几个文件分别导入`);
      return;
    }

    // 首行保持原样（不 trim）—— 分隔符是逗号还是制表符，要靠它判断。
    // trim 掉末尾的制表符会吃掉最后一个空列。
    const firstLine = importText.replace(/^﻿/, '').split('\n').filter(l => l.trim())[0] || '';
    const drafts = parseImportRows(importText, looksLikeHeader(firstLine));

    if (drafts.length === 0) { await tell('未识别到有效数据', '检查一下第一行是不是「日期,事项」这样的表头，或者内容是不是少了日期列。'); return; }

    setImportPreview(drafts.map(d => ({
      id: newId(),
      title: d.title,
      date: d.date,
      time: d.time,
      endTime: d.endTime,
      endDate: d.endDate,
      location: d.location,
      people: d.people,
      raw: d.raw,
      updatedAt: Date.now(),
      type: d.type,
      completed: false,
    })));
  };

  const confirmImport = async () => {
    if (!importPreview) return;
    // 没日期的行不能导入 —— 落今天是猜，猜出来的日期会悄悄错掉
    const missingDate = importPreview.filter(e => !e.date);
    if (missingDate.length) {
      await tell('有行没填日期', `还有 ${missingDate.length} 行没填日期 —— 请先补上再导入。`);
      return;
    }
    // 去重与推送都要在 setEvents 的 updater 外面做 ——
    // updater 必须是纯函数。放在里面发网络请求，React 的 StrictMode
    // 会把它跑两遍，结果是同一批记录被推送两次。
    const existing = new Set(events.map(e => `${e.date}|${e.time}|${e.title}`));
    const deduped = importPreview.filter(e => !existing.has(`${e.date}|${e.time}|${e.title}`));
    setEvents(prev => [...prev, ...deduped]);
    if (isOnline && token) {
      for (const e of deduped) {
        enqueueChange({ id: e.id, op: 'create', payload: toPayload(e), ts: e.updatedAt || Date.now() });
      }
    }
    // 保存导入历史
    const group = { id: newId(), name: `导入 ${new Date().toLocaleDateString('zh-CN')}`, count: deduped.length, time: new Date().toISOString() };
    const groups = [group, ...importGroups].slice(0, 20);
    setImportGroups(groups);
    localStorage.setItem('schedule_import_groups', JSON.stringify(groups));
    setImportPreview(null);
    setShowImportModal(false);
  };

  const deleteImportGroup = (id: string) => {
    const groups = importGroups.filter(g => g.id !== id);
    setImportGroups(groups);
    localStorage.setItem('schedule_import_groups', JSON.stringify(groups));
  };

  // ==================== 日历渲染 ====================

  // 当天的安排与事项。
  // 注意：这里不按 isOnline（=已激活）过滤 —— 本地记下的事，
  // 无论有没有激活都得看得见。以前加了 isOnline 判断，结果是
  // 「这一周」里能看到、「今天的安排」却是空的，同一份数据两个说法，
  // 用户会以为记录丢了。现在两处口径一致。
  // 某天涉及的事件。
  // 跨日事件在它占的**每一天**都要出现 —— 点 11/20 也能看到 11/18-11/22 那件事。
  const coversDate = (e: ScheduleEvent, d: string) =>
    e.date === d || (!!e.endDate && e.endDate > e.date && d > e.date && d <= e.endDate);

  const dayEvents = (detailDate)
    ? events.filter(e => coversDate(e, detailDate) && e.type === 'event').sort((a, b) => a.time.localeCompare(b.time))
    : [];
  // 项目实体不在这里出现 —— 它是「文件夹」，不是某天发生的事。
  // （以前用 type !== 'event'，项目被当成任务显示了，
  //   结果新建的项目看起来像「11 月 3 日多了一条日程」）
  const dayTasks = (detailDate)
    ? events.filter(e => coversDate(e, detailDate) && e.type === 'task')
        .sort((a, b) => (a.completed ? 1 : 0) - (b.completed ? 1 : 0) || b.updatedAt - a.updatedAt)
    : [];

  // 四宫格清单浮层里要显示哪些记录。
  // 「日程/任务/项目」数的是本月（跟月历看到的一致）；
  // 「完成」是过往累计已完成的 —— 所以它可以远大于前三个。
  const monthPrefix = `${monthAnchor.getFullYear()}-${String(monthAnchor.getMonth() + 1).padStart(2, '0')}-`;
  const statItems: ScheduleEvent[] = (() => {
    if (statKind === 'completed') return events.filter(e => e.completed && e.type !== 'project');
    const inMonth = events.filter(e => e.date.startsWith(monthPrefix));
    // 挂在项目下的事不在日程/任务格里 —— 它们在项目卡里看
    if (statKind === 'event') return inMonth.filter(e => e.type === 'event' && !e.projectId);
    if (statKind === 'task') return inMonth.filter(e => e.type === 'task' && !e.projectId);
    // 项目没有日期（它是容器），所以是全部项目，不按月算
    return events.filter(e => e.type === 'project');
  })();

  // 项目 id → 它下面的事件。项目卡第二级要用。
  const projectItems: Record<string, ScheduleEvent[]> = (() => {
    const map: Record<string, ScheduleEvent[]> = {};
    for (const e of events) {
      if (!e.projectId) continue;
      (map[e.projectId] = map[e.projectId] || []).push(e);
    }
    return map;
  })();

  // 全部项目（编辑表单里的项目下拉要用）
  const allProjects = events.filter(e => e.type === 'project');


  // ==================== UI ====================

  return (
    // h-screen：整个页面锁定一屏高，不滚动。
    // 月历卡片靠 flex-1 撑满剩余高度 —— 这样屏幕下半部分被卡片占住，
    // 壁纸不会空出一大块。
    // 输入区是 fixed 钉在底部的，文档流里由 InputArea 的占位块让出空间。
    <main className="h-screen flex flex-col overflow-hidden">
      {/* v1.0 更新弹窗 */}
      {showVersionModal && (
        <div className="fixed inset-0 z-[70] flex items-center justify-center bg-black/50 backdrop-blur-sm p-4" onClick={dismissVersionModal}>
          <div className="bg-white rounded-2xl w-[var(--card-w)] max-w-full p-6 shadow-lg animate-slide-up" onClick={e => e.stopPropagation()}>
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

      {/* Header —— pt 要加上顶部安全区：
          加到桌面（standalone）打开时，iPhone 的状态栏是盖在内容上的，
          不留这一块，顶栏的标题和按钮会被状态栏压住。

          形态：以前是全宽白条（bg-white + 底边框），
          现在改成悬浮的圆角卡片 —— 壁纸能透过四周的缝看见，
          顶栏本身半透明 + 毛玻璃。 */}
      <header className="sticky top-0 z-50 px-3 pt-[calc(var(--sat)+0.75rem)] pb-1 sm:px-4">
        <div className="card-glass max-w-full mx-auto rounded-2xl border border-white/60 shadow-[0_2px_16px_rgba(28,28,28,0.06)] px-4 py-3 sm:px-5 sm:py-3.5">
          <div className="flex flex-wrap justify-between items-center gap-y-2 max-w-full">
            <h1 className="text-xl font-semibold text-[#1C1C1C] flex items-center gap-2 tracking-tight shrink-0">
              <img src="/icon-192x192.png" alt="" className="w-7 h-7 rounded" /> 菠萝日程
            </h1>
            <div className="flex items-center gap-1 flex-wrap">
              {/* 设置 —— 日历订阅/导出/导入/模板/退出都收进这张卡。
                  顶栏原来挤了 7 个图标，手机上根本认不清哪个是哪个。 */}
              <button onClick={() => setShowSettings(true)}
                className="w-9 h-9 rounded-lg hover:bg-white/70 transition-colors flex items-center justify-center" aria-label="设置" title="设置">
                <svg className="w-4 h-4 text-[#5C5C5C]" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" /><path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /></svg>
              </button>
              {/* 反馈 */}
              <button onClick={() => setShowFeedback(true)}
                className="w-9 h-9 rounded-lg hover:bg-white/70 transition-colors flex items-center justify-center" aria-label="反馈" title="反馈建议">
                <svg className="w-4 h-4 text-[#5C5C5C]" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-4l-4 4z" /></svg>
              </button>
              {/* 帮助 = 说明 + 更新讯息 */}
              <button onClick={() => setShowHelp(true)}
                className="w-9 h-9 rounded-lg hover:bg-white/70 transition-colors flex items-center justify-center" aria-label="帮助" title="使用说明">
                <svg className="w-4 h-4 text-[#5C5C5C]" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
              </button>
              {/* 同步状态点 —— 激活后是绿的 */}
              <div className="relative group">
                <span className={`w-2.5 h-2.5 rounded-full block cursor-default ${
                  !isOnline ? 'bg-[#D9D4CF]'
                    : syncState === 'syncing' ? 'bg-[#ED6A3B] animate-pulse'
                    : syncState === 'offline' ? 'bg-[#D9D4CF]'
                    : 'bg-[#059669] shadow-[0_0_6px_rgba(5,150,105,0.4)]'
                }`} />
                <div className="absolute right-0 top-6 hidden group-hover:block bg-[#1C1C1C] text-white text-xs rounded-lg px-3 py-2 whitespace-nowrap z-[60] shadow-lg">
                  {isOnline ? (
                    <><span className="text-[#34d399]">●</span> {user?.email}<br /><span className="text-[#A0A0A0]">
                      {syncState === 'syncing' ? '正在同步…'
                        : syncState === 'offline' ? `离线待同步${pendingCount ? ` · ${pendingCount} 条待传` : ''}`
                        : '已同步 · 多设备自动同步'}
                    </span></>
                  ) : (
                    '未激活 · 记下的事只在这台设备上'
                  )}
                </div>
              </div>
              {/* 刷新 */}
              {isOnline && (
                <button onClick={() => void syncFromCloud()} disabled={syncState === 'syncing'}
                  className="w-9 h-9 rounded-lg hover:bg-white/70 transition-colors flex items-center justify-center" aria-label="同步" title="同步">
                  <RefreshCw className={`w-4 h-4 text-[#5C5C5C] ${syncState === 'syncing' ? 'animate-spin' : ''}`} />
                </button>
              )}
            </div>
          </div>
        </div>
      </header>

      {/* 激活弹窗 */}
      {showActivate && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/30" onClick={() => { if (!activateLoading) { setShowActivate(false); setActivateStep('email'); setActivateError(''); } }}>
          <div className="bg-white rounded-2xl p-6 w-[var(--card-w)] max-w-full shadow-lg" onClick={e => e.stopPropagation()}>
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
          <div className="bg-white rounded-2xl p-6 w-[var(--card-w)] max-w-full shadow-lg" onClick={e => e.stopPropagation()}>
            <h2 className="text-lg font-semibold text-[#1C1C1C] mb-1">导出到手机日历</h2>
            <p className="text-sm text-[#A0A0A0] mb-5">iPhone 相机扫码自动订阅，或复制链接手动添加</p>

            {calError ? (
              <div className="bg-[#FFF5F0] border border-[#F5D9CC] rounded-lg p-4 mb-4">
                <p className="text-sm text-[#C2410C]">{calError}</p>
              </div>
            ) : (
              <>
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
              </>
            )}

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
          <div className="bg-white rounded-2xl p-6 w-[var(--card-w)] max-w-full shadow-lg" onClick={e => e.stopPropagation()}>
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
          <div className="bg-white rounded-2xl p-6 w-[var(--card-w)] max-w-full shadow-lg max-h-[80vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
            <div className="flex justify-between items-center mb-5">
              <h2 className="text-lg font-semibold text-[#1C1C1C]">使用说明 <span className="text-[10px] font-normal text-[#9A9790]">v4.0</span></h2>
              <button onClick={() => setShowHelp(false)} className="w-8 h-8 rounded-lg hover:bg-[#F3F1ED] text-[#A0A0A0] flex items-center justify-center transition-colors">&times;</button>
            </div>

            <div className="space-y-5">
              <div>
                <h3 className="text-sm font-semibold text-[#1C1C1C] mb-1.5">记一句就够</h3>
                <p className="text-sm text-[#5C5C5C] leading-relaxed">直接写或直接说，如「<span className="text-[#ED6A3B]">后天下午3点买菜</span>」「<span className="text-[#ED6A3B]">上周五组会</span>」。日期、时间自动认出来。<br /><span className="text-xs text-[#A0A0A0]">认不出来会标一个「待确认」，点一下改掉就行 —— 猜错了也能改</span></p>
              </div>

              <div>
                <h3 className="text-sm font-semibold text-[#1C1C1C] mb-1.5">看一周</h3>
                <p className="text-sm text-[#5C5C5C] leading-relaxed">上面是一周的时间轴，下面是「这一周」的记录，按天分好组。左右翻看别的周。<br /><span className="text-xs text-[#A0A0A0]">手机上看到的是「今天」加「这一周」 —— 写周报时抄的就是这一屏</span></p>
              </div>

              <div>
                <h3 className="text-sm font-semibold text-[#1C1C1C] mb-1.5">语音输入</h3>
                <p className="text-sm text-[#5C5C5C] leading-relaxed">点麦克风开始说，再点一下结束。说完直接记上。一口气说两件事，会拆成两条。<br /><span className="text-xs text-[#A0A0A0]">用不了麦克风也不耽误 —— 会自动换浏览器语音，再不行就直接打字</span></p>
              </div>

              <div>
                <h3 className="text-sm font-semibold text-[#1C1C1C] mb-1.5">多设备同步</h3>
                <p className="text-sm text-[#5C5C5C] leading-relaxed">点右上角「激活」→ 输入邮箱 → 收验证码 → 填上 → 完成。之后所有设备自动同步。<br /><span className="text-xs text-[#A0A0A0]">没网时先记下来，网一恢复自动补传，不会丢</span></p>
              </div>

              <div>
                <h3 className="text-sm font-semibold text-[#1C1C1C] mb-1.5">导入课表</h3>
                <p className="text-sm text-[#5C5C5C] leading-relaxed">点导入，选 Excel 或 CSV 文件。每行都能先看看再改，确认了才进来。<br /><span className="text-xs text-[#A0A0A0]">认不出的列会问你什么意思，不瞎猜</span></p>
              </div>

              <div>
                <h3 className="text-sm font-semibold text-[#1C1C1C] mb-1.5">导出</h3>
                <p className="text-sm text-[#5C5C5C] leading-relaxed">点导出，选一段时间，存成表格、文本或 Excel 都能开。<br /><span className="text-xs text-[#A0A0A0]">三种格式内容一样，挑顺手的那个</span></p>
              </div>

              <div>
                <h3 className="text-sm font-semibold text-[#1C1C1C] mb-1.5">加到手机桌面</h3>
                <p className="text-sm text-[#5C5C5C] leading-relaxed">iPhone Safari 点分享 → 添加到主屏幕<br />Android Chrome 点菜单 → 添加到主屏幕<br /><span className="text-xs text-[#A0A0A0]">加完像 App 一样打开，更顺手</span></p>
              </div>

              <div>
                <h3 className="text-sm font-semibold text-[#1C1C1C] mb-1.5">日历订阅</h3>
                <p className="text-sm text-[#5C5C5C] leading-relaxed">激活后点日历图标 → iPhone 相机扫一下 → 自动订阅。日程会出现在系统日历里。</p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 导入弹窗（两步模式） */}
      {showImportModal && (
        <div className="fixed inset-0 z-[65] flex items-center justify-center bg-black/40 backdrop-blur-sm p-4" onClick={() => { setShowImportModal(false); setImportPreview(null); }}>
          <div className="bg-white rounded-2xl w-[var(--card-w)] max-w-full max-h-[85vh] flex flex-col shadow-lg" onClick={e => e.stopPropagation()}>
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
                      <div className="flex gap-2 items-center flex-wrap">
                        <input type="date" value={e.date} placeholder="日期" onChange={ev => {
                          const next = [...importPreview]; next[i] = { ...next[i], date: ev.target.value }; setImportPreview(next);
                        }} className={`px-2 py-1 border rounded text-xs bg-white outline-none focus:border-[#1C1C1C] ${e.date ? 'border-[#E8E4DF]' : 'border-[#ED6A3B] bg-[#FFF5F0]'}`} />
                        <input type="time" value={e.time} onChange={ev => {
                          const next = [...importPreview]; next[i] = { ...next[i], time: ev.target.value }; setImportPreview(next);
                        }} className="px-2 py-1 border border-[#E8E4DF] rounded text-xs bg-white outline-none focus:border-[#1C1C1C] w-24" />
                        <input type="time" value={e.endTime} placeholder="结束" onChange={ev => {
                          const next = [...importPreview]; next[i] = { ...next[i], endTime: ev.target.value }; setImportPreview(next);
                        }} className="px-2 py-1 border border-[#E8E4DF] rounded text-xs bg-white outline-none focus:border-[#1C1C1C] w-20" />
                        {/* 跨日的结束日期 —— 填了就占这几天，月历上连成一条 */}
                        <input type="date" value={e.endDate || ''} title="结束日期（跨日）" onChange={ev => {
                          const next = [...importPreview]; next[i] = { ...next[i], endDate: ev.target.value }; setImportPreview(next);
                        }} className="px-2 py-1 border border-[#E8E4DF] rounded text-xs bg-white outline-none focus:border-[#1C1C1C] w-[122px]" />
                        <input type="text" value={e.location} placeholder="地点" onChange={ev => {
                          const next = [...importPreview]; next[i] = { ...next[i], location: ev.target.value }; setImportPreview(next);
                        }} className="px-2 py-1 border border-[#E8E4DF] rounded text-xs bg-white outline-none focus:border-[#1C1C1C] flex-1 min-w-20" />
                        <input type="text" value={e.people} placeholder="人员" onChange={ev => {
                          const next = [...importPreview]; next[i] = { ...next[i], people: ev.target.value }; setImportPreview(next);
                        }} className="px-2 py-1 border border-[#E8E4DF] rounded text-xs bg-white outline-none focus:border-[#1C1C1C] flex-1 min-w-20" />
                      </div>
                      {!e.date && (
                        <p className="text-xs text-[#ED6A3B]">这一行没有日期 —— 文件里没写，导入前请补上</p>
                      )}
                      {!e.time && !e.endTime && (
                        <p className="text-xs text-[#ED6A3B]">这一行没有时间 —— 文件里没写，导入前请补上</p>
                      )}
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
                  <p className="text-xs text-[#A0A0A0]">每行一条，格式：日期,开始时间,结束时间,事项,地点,人员,备注（无时间的自动归为任务）。也可以直接粘贴 Excel 里复制的表格</p>
                  <textarea value={importText} onChange={e => setImportText(e.target.value)}
                    placeholder={`日期,开始时间,结束时间,事项,地点,人员,备注\n2026-11-02,08:50,10:30,初始训练-模拟航班,青浦B777经济静态舱,张教员\n2026-11-03,12:50,,团队周会,C楼201,全组\n2026-11-04,,,整理培训材料,,,培训材料归档`}
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
                      <p className="text-xs text-[#8A8A8A] mb-2">导入历史</p>
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

      {/* ==================== 三个浮层 ====================
          点顶栏齿轮 / 点日历某天 / 点四宫格某格 → 弹卡片，下面全模糊。

          模糊遮罩 z-[60]，输入框 z-[100] —— 输入框在遮罩之上，
          所以浮层打开时它依然清晰可输入（它是「当前编辑目标」的输入框）。 */}

      {showSettings && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/30 backdrop-blur-md p-4"
          onClick={() => setShowSettings(false)}>
          <div onClick={e => e.stopPropagation()}>
            <SettingsCard
              isOnline={isOnline}
              onActivate={() => setShowActivate(true)}
              onCalSubscribe={handleShowCalModal}
              onExport={() => setShowExportModal(true)}
              onImport={() => { setImportText(''); setImportPreview(null); setShowImportModal(true); }}
              onTemplate={generateCsvTemplate}
              onLogout={handleLogout}
              onClose={() => setShowSettings(false)}
            />
          </div>
        </div>
      )}

      {showDayCard && detailDate && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/30 backdrop-blur-md p-4"
          onClick={() => { setShowDayCard(false); setEditingEventId(null); }}>
          <div onClick={e => e.stopPropagation()}>
            <DayCard
              date={detailDate}
              dayEvents={dayEvents}
              dayTasks={dayTasks}
              editingEventId={editingEventId}
              editForm={editForm}
              projects={allProjects}
              onEditFormChange={setEditForm}
              onStartEdit={startEdit}
              onCancelEdit={() => { setEditingEventId(null); setEditForm({ title: '', date: '', time: '', endTime: '', endDate: '', projectId: '', location: '', people: '' }); }}
              onSaveEdit={saveEdit}
              onToggleCompleted={toggleTaskCompleted}
              onDelete={deleteEvent}
              onClose={() => { setShowDayCard(false); setEditingEventId(null); }}
            />
          </div>
        </div>
      )}

      {showStatCard && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/30 backdrop-blur-md p-4"
          onClick={() => setShowStatCard(false)}>
          <div onClick={e => e.stopPropagation()}>
            <StatCard
              kind={statKind}
              title={{ event: '日程', task: '任务', project: '项目', completed: '已完成' }[statKind]}
              items={statItems}
              canAdd={statKind === 'task' || statKind === 'project'}
              onAdd={() => { if (statKind === 'task') setStatAdding(true); }}
              projectItems={projectItems}
              onCreateProject={createProject}
              onRenameProject={(id, name) => patchProject(id, { title: name })}
              onSaveProjectNote={(id, note) => patchProject(id, { raw: note })}
              onDeleteProject={deleteProject}
              onToggleCompleted={toggleTaskCompleted}
              onDelete={deleteEvent}
              onClose={() => setShowStatCard(false)}
            />
          </div>
        </div>
      )}

      {/* 内容区：月历卡片 + 四宫格。
          桌面端跟移动端一样 —— 不再「左周视图 + 右明细卡」并排。
          月历在宽屏上格子更大，看得更清楚；明细改成点日期后弹浮层。

          min-h-0：flex 子项默认 min-height:auto，
          不加的话月历的 flex-1 撑不开，四宫格会把整页顶出视口。 */}
      <div className="flex-1 flex flex-col gap-2.5 mx-3 mt-3 pb-2 min-h-0">

        <MonthView
          year={monthAnchor.getFullYear()}
          month={monthAnchor.getMonth() + 1}
          events={events.map(e => ({
            id: e.id, title: e.title, date: e.date, time: e.time,
            endTime: e.endTime, endDate: e.endDate, projectId: e.projectId,
            location: e.location, people: e.people,
            type: e.type, completed: e.completed,
          }))}
          today={new Date()}
          onPrevMonth={() => setMonthAnchor(d => new Date(d.getFullYear(), d.getMonth() - 1, 1))}
          onNextMonth={() => setMonthAnchor(d => new Date(d.getFullYear(), d.getMonth() + 1, 1))}
          onDateClick={(d) => { setDetailDate(d); setShowDayCard(true); }}
          onStatClick={(k) => { setStatKind(k); setShowStatCard(true); }}
        />
      </div>

      {/* 输入区 —— 唯一输入入口：麦克风 + 文本框 + 同步状态 */}
      {/* 导出弹窗 */}
      {showExportModal && (
        <div className="fixed inset-0 z-[70] bg-black/40 flex items-center justify-center p-4"
          onClick={() => setShowExportModal(false)}>
          <div className="bg-white rounded-2xl w-[var(--card-w)] max-w-full max-h-[88vh] flex flex-col shadow-2xl"
            onClick={ev => ev.stopPropagation()}>
            <div className="flex justify-between items-center p-5 border-b border-[#E8E4DF] shrink-0">
              <h2 className="font-semibold text-[#1C1C1C]">导出</h2>
              <button onClick={() => setShowExportModal(false)}
                className="w-8 h-8 rounded-lg hover:bg-[#F3F1ED] text-[#A0A0A0] flex items-center justify-center" aria-label="关闭">×</button>
            </div>

            <div className="p-5 space-y-5 overflow-y-auto flex-1">
              {/* 范围 */}
              <div>
                <label className="text-xs text-[#8A8A8A] mb-2 block">哪段时间</label>
                <div className="grid grid-cols-4 gap-2">
                  {([['today', '今天'], ['week', '本周'], ['month', '本月'], ['custom', '自定义']] as const).map(([v, label]) => (
                    <button key={v} onClick={() => setExportRange(v)}
                      className={`h-10 rounded-lg text-sm border transition-colors ${
                        exportRange === v
                          ? 'bg-[#ED6A3B] text-white border-[#ED6A3B]'
                          : 'bg-white text-[#5C5C5C] border-[#E8E4DF] hover:bg-[#F3F1ED]'
                      }`}>
                      {label}
                    </button>
                  ))}
                </div>
                {exportRange === 'custom' && (
                  <div className="flex gap-2 items-center mt-3">
                    <input type="date" value={exportFrom} onChange={ev => setExportFrom(ev.target.value)}
                      className="px-2 py-1.5 border border-[#E8E4DF] rounded text-sm bg-white outline-none focus:border-[#1C1C1C]" />
                    <span className="text-[#A0A0A0] text-xs">到</span>
                    <input type="date" value={exportTo} onChange={ev => setExportTo(ev.target.value)}
                      className="px-2 py-1.5 border border-[#E8E4DF] rounded text-sm bg-white outline-none focus:border-[#1C1C1C]" />
                  </div>
                )}
              </div>

              {/* 格式 */}
              <div>
                <label className="text-xs text-[#8A8A8A] mb-2 block">导出成什么</label>
                <div className="space-y-2">
                  {([
                    ['text', '文本', '贴邮件、写周报'],
                    ['csv', 'CSV', '用 Excel 打开继续加工'],
                    ['xlsx', 'XLSX', '直接是表格，发给同事'],
                  ] as const).map(([v, label, hint]) => (
                    <button key={v} onClick={() => setExportFormat(v)}
                      className={`w-full text-left px-3 py-2.5 rounded-lg border transition-colors ${
                        exportFormat === v
                          ? 'border-[#ED6A3B] bg-[#FFF5F0]'
                          : 'border-[#E8E4DF] bg-white hover:bg-[#F3F1ED]'
                      }`}>
                      <div className="text-sm font-medium text-[#1C1C1C]">{label}</div>
                      <div className="text-xs text-[#A0A0A0] mt-0.5">{hint}</div>
                    </button>
                  ))}
                </div>
              </div>

              <p className="text-xs text-[#A0A0A0]">
                这个区间共 {exportRows().length} 条
                {exportRows().length === 0 && ' —— 换个时间段试试'}
              </p>
            </div>

            <div className="flex gap-2 p-5 border-t border-[#E8E4DF] shrink-0">
              <button onClick={() => setShowExportModal(false)}
                className="flex-1 h-11 rounded-lg border border-[#E8E4DF] text-sm text-[#5C5C5C] hover:bg-[#F3F1ED] transition-colors">取消</button>
              <button onClick={doExport}
                className="flex-1 h-11 bg-[#ED6A3B] text-white rounded-lg text-sm font-semibold hover:bg-[#D45D2E] transition-colors">导出</button>
            </div>
          </div>
        </div>
      )}

      <InputArea
        apiBase={API_BASE}
        token={token}
        onSubmit={handleParsed}
        isNarrow={isNarrow}
      />

      {/* 开发期标注器 —— 只在 next dev 出现，生产构建整块不渲染。
          改 UI 时不用靠文字描述「指哪」，点一下元素就有精确信息。 */}
      {process.env.NODE_ENV === 'development' && <Inspector />}

      {/* 应用内弹窗 —— 确认/提示。原生 confirm 在 iOS PWA 里会被静默忽略。 */}
      <DialogHost dialog={dialog} close={close} />
    </main>
  );
}
