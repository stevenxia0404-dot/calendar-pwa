// 本地操作队列 —— v4.0 同步机制的客户端一半
//
// 为什么要有它
// v3 的写操作是「直接发，失败静默」。一次失败，那条记录就永远只在本机，
// 其他设备看不到，而用户毫无感知 —— 注释里写的「下次同步修复」并不成立，
// 因为同步逻辑只拉不推。
//
// v4.0 的做法：所有写操作先进队列，再由队列按序重放到服务端。
// 断网时操作攒着，联网后自动补传。用户什么都不用管。
//
// 队列的核心是「按 id 折叠」——同一条记录的连续操作只保留最后一个，
// 而不是攒一串。这样离线期间改五次标题，重放时只发一次。
//
// 队列里的操作都必须是幂等的：重放两次结果一样。
// 这也是为什么服务端把 /events/:id/toggle 改成接受显式的 completed 值
// —— 服务端翻转的接口重放两次会互相抵消。

export type SyncOpType = 'create' | 'update' | 'delete';

/** 上传给服务端的记录内容（不含 id 与时间戳 —— 时间戳由服务端生成） */
export interface SyncPayload {
  title: string;
  date: string;
  time: string;
  endTime: string;
  /** 跨日事件的结束日期（含当天）；空串 = 不跨日 */
  endDate: string;
  /** 归属的项目 id；空串 = 不属于任何项目 */
  projectId: string;
  location: string;
  people: string;
  raw: string;
  /** 'event' 有时间 · 'task' 没时间 · 'project' 项目 */
  type: 'event' | 'task' | 'project';
  completed: boolean;
  dateConfirmed: 0 | 1;
}

export interface SyncOp {
  /** 记录 id */
  id: string;
  op: SyncOpType;
  /** create / update 的内容；delete 不需要 */
  payload?: SyncPayload;
  /** 入队时刻，仅用于展示与稳定排序，不参与冲突判定 */
  ts: number;
}

const QUEUE_KEY = 'schedule_sync_queue';

/**
 * 按 id 折叠队列。
 *
 * 折叠规则（后到的操作覆盖先到的）：
 *   create + update → create（用新内容，服务端还不认识这条）
 *   create + delete → 移除（这条从没到过服务端，删掉等于没建过）
 *   update + update → update（用新内容）
 *   update + delete → delete（删除是最后一个意图）
 *   delete + 任意   → delete（删除吸收一切后续操作）
 *   create + create → create（用新内容）
 *
 * 返回新数组，不改原数组。
 */
export function enqueueOp(queue: SyncOp[], op: SyncOp): SyncOp[] {
  const rest = queue.filter(o => o.id !== op.id);
  const prev = queue.find(o => o.id === op.id);

  // delete 吸收一切：删除之后再编辑/新建都按删除算。
  // 界面上删掉的记录会消失，正常流程不会走到这个分支；
  // 走到时保守处理（宁可少一条，不可多一条）。
  if (prev && prev.op === 'delete') return [...rest, { ...op, op: 'delete', payload: undefined }];

  if (prev && prev.op === 'create' && op.op === 'delete') {
    // 这条从没到过服务端，直接从队列里抹掉
    return rest;
  }

  const nextOp: SyncOpType =
    prev && prev.op === 'create' && op.op === 'update' ? 'create' : op.op;

  return [...rest, { ...op, op: nextOp }];
}

/** 移除某条操作（重放成功后调用） */
export function removeOp(queue: SyncOp[], id: string): SyncOp[] {
  return queue.filter(o => o.id !== id);
}

/** 队列里所有待推送的 id */
export function pendingIds(queue: SyncOp[]): Set<string> {
  return new Set(queue.map(o => o.id));
}

/**
 * 服务端返回的一条记录，已转成与本地相同的形态。
 * deleted 为 true 表示这是墓碑（服务端已删除），value 为 null。
 */
export interface CloudItem<T> {
  id: string;
  updatedAt: number;
  deleted: boolean;
  value: T | null;
}

/**
 * 合并「云端记录」与「本地记录」，产出最终应显示的集合。
 *
 * 这是整个同步机制的核心判定，纯函数所以可单测。
 *
 * @param local   本地现有记录
 * @param cloud   服务端返回的记录（含墓碑）
 * @param pending 队列里待推送的 id —— 这些以本地为准，云端版本一律忽略
 * @param full    是否全量拉取。全量才做删除对账，增量不做
 *                （增量只管「变了的」，没变的不该被动）
 */
export function reconcile<T extends { id: string; updatedAt: number }>(
  local: T[],
  cloud: CloudItem<T>[],
  pending: Set<string>,
  full: boolean,
): T[] {
  const map = new Map(local.map(e => [e.id, e]));
  const liveServerIds = new Set<string>();

  for (const ce of cloud) {
    // 墓碑：这条在服务端被删了，本地也要删。
    // 但如果本地还有待推送的操作（比如刚删又改），以本地为准。
    if (ce.deleted) {
      if (!pending.has(ce.id)) map.delete(ce.id);
      continue;
    }

    liveServerIds.add(ce.id);

    // 本地待推送的变更优先，不能被云端版本盖掉
    if (pending.has(ce.id)) continue;

    const l = map.get(ce.id);
    // 用 >= 而不是 >：同一毫秒的两次写入，服务端返回的应算更新
    if ((!l || ce.updatedAt >= l.updatedAt) && ce.value) {
      map.set(ce.id, ce.value);
    }
  }

  // 全量拉取时的删除对账：服务端没有的本地记录，如果它以前同步过，
  // 说明是被别处删了 —— 也要跟着删。
  // 没同步过的本地记录（从没上传）不能删，否则未登录时记的东西
  // 一登录就没了。靠 synced 标记区分。
  if (full) {
    for (const [id, ev] of Array.from(map)) {
      if (pending.has(id)) continue;
      if (liveServerIds.has(id)) continue;
      const wasSynced = (ev as unknown as { synced?: boolean }).synced;
      if (wasSynced) map.delete(id);
    }
  }

  return Array.from(map.values());
}

// ==================== 存储 ====================

/** 读取队列。存储不可用（隐私模式、配额满）时返回空队列，不抛 */
export function readQueue(): SyncOp[] {
  try {
    const raw = localStorage.getItem(QUEUE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(o => o && typeof o.id === 'string' && typeof o.op === 'string');
  } catch {
    return [];
  }
}

/** 写回队列。存储不可用时静默失败 —— 队列丢了顶多丢一次同步，
 *  但绝不能因此让整个应用崩掉 */
export function writeQueue(queue: SyncOp[]): boolean {
  try {
    localStorage.setItem(QUEUE_KEY, JSON.stringify(queue));
    return true;
  } catch {
    return false;
  }
}

/** 清空队列（登出时用 —— 队列属于某个账号） */
export function clearQueue(): void {
  try {
    localStorage.removeItem(QUEUE_KEY);
  } catch {
    /* 忽略 */
  }
}
