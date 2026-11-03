// 本地操作队列的单测
// 折叠规则与合并判定是整个同步机制的核心 —— 一旦错了就是静默数据丢失。
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  enqueueOp,
  removeOp,
  pendingIds,
  reconcile,
} from '../src/lib/syncQueue.ts';
import type { SyncOp, SyncPayload, CloudItem } from '../src/lib/syncQueue.ts';

const payload = (title: string): SyncPayload => ({
  title,
  date: '2026-11-01',
  time: '09:00',
  endTime: '',
  endDate: '',
  location: '',
  people: '',
  raw: '',
  type: 'event',
  completed: false,
  dateConfirmed: 1,
});

const op = (id: string, o: SyncOp['op'], title = 'x', ts = 1): SyncOp =>
  o === 'delete' ? { id, op: o, ts } : { id, op: o, payload: payload(title), ts };

describe('队列折叠 —— 同一条记录只保留最后一个意图', () => {
  test('create + update → create（用新内容，服务端还不认识这条）', () => {
    const q = enqueueOp([op('a', 'create', '原标题')], op('a', 'update', '新标题'));
    assert.equal(q.length, 1);
    assert.equal(q[0].op, 'create');
    assert.equal(q[0].payload?.title, '新标题');
  });

  test('create + delete → 整条移除（从没到过服务端，删了等于没建过）', () => {
    const q = enqueueOp([op('a', 'create')], op('a', 'delete'));
    assert.equal(q.length, 0);
  });

  test('update + update → update（用新内容）', () => {
    const q = enqueueOp([op('a', 'update', '一')], op('a', 'update', '二'));
    assert.equal(q.length, 1);
    assert.equal(q[0].op, 'update');
    assert.equal(q[0].payload?.title, '二');
  });

  test('update + delete → delete（删除是最后一个意图）', () => {
    const q = enqueueOp([op('a', 'update')], op('a', 'delete'));
    assert.equal(q.length, 1);
    assert.equal(q[0].op, 'delete');
    assert.equal(q[0].payload, undefined);
  });

  test('delete + update → delete（删除吸收一切后续操作）', () => {
    const q = enqueueOp([op('a', 'delete')], op('a', 'update'));
    assert.equal(q.length, 1);
    assert.equal(q[0].op, 'delete');
  });

  test('delete + create → delete', () => {
    const q = enqueueOp([op('a', 'delete')], op('a', 'create'));
    assert.equal(q.length, 1);
    assert.equal(q[0].op, 'delete');
  });

  test('不同 id 互不影响', () => {
    const q = enqueueOp([op('a', 'create')], op('b', 'create'));
    assert.equal(q.length, 2);
  });

  test('折叠不会改原数组', () => {
    const orig = [op('a', 'create')];
    enqueueOp(orig, op('a', 'update'));
    assert.equal(orig.length, 1);
    assert.equal(orig[0].op, 'create');
  });
});

describe('队列基础操作', () => {
  test('removeOp 按 id 移除', () => {
    const q = [op('a', 'create'), op('b', 'create')];
    assert.equal(removeOp(q, 'a').length, 1);
    assert.equal(removeOp(q, 'zzz').length, 2);
  });

  test('pendingIds 给出所有待推送的 id', () => {
    const ids = pendingIds([op('a', 'create'), op('b', 'delete')]);
    assert.equal(ids.size, 2);
    assert.ok(ids.has('a'));
    assert.ok(ids.has('b'));
  });
});

describe('合并判定 —— 云端与本地谁赢', () => {
  interface L { id: string; updatedAt: number; title: string; synced?: boolean }

  const local = (id: string, updatedAt: number, extra: Partial<L> = {}): L =>
    ({ id, updatedAt, title: '本地', ...extra });

  const cloud = (id: string, updatedAt: number, deleted = false): CloudItem<L> => ({
    id,
    updatedAt,
    deleted,
    value: deleted ? null : { id, updatedAt, title: '云端', synced: true },
  });

  test('云端更新 → 采信云端', () => {
    const out = reconcile([local('a', 100)], [cloud('a', 200)], new Set(), false);
    assert.equal(out.length, 1);
    assert.equal(out[0].updatedAt, 200);
    assert.equal(out[0].title, '云端');
  });

  test('云端更旧 → 保留本地', () => {
    const out = reconcile([local('a', 300)], [cloud('a', 200)], new Set(), false);
    assert.equal(out[0].updatedAt, 300);
    assert.equal(out[0].title, '本地');
  });

  test('时间相同 → 采信云端（同一毫秒的两次写入，服务端返回的算更新）', () => {
    const out = reconcile([local('a', 200)], [cloud('a', 200)], new Set(), false);
    assert.equal(out[0].updatedAt, 200);
    assert.equal(out[0].title, '云端');
  });

  test('云端有本地没有的 → 新增', () => {
    const out = reconcile([], [cloud('b', 200)], new Set(), false);
    assert.equal(out.length, 1);
    assert.equal(out[0].id, 'b');
  });

  test('墓碑 → 本地也删（删除能跨设备传播）', () => {
    const out = reconcile([local('a', 100)], [cloud('a', 200, true)], new Set(), false);
    assert.equal(out.length, 0);
  });

  test('墓碑但本地有待推送操作 → 以本地为准，不删', () => {
    const out = reconcile(
      [local('a', 100)],
      [cloud('a', 200, true)],
      new Set(['a']),
      false,
    );
    assert.equal(out.length, 1);
  });

  test('本地有待推送操作 → 云端版本盖不掉它', () => {
    const out = reconcile([local('a', 100)], [cloud('a', 999)], new Set(['a']), false);
    assert.equal(out[0].updatedAt, 100);
    assert.equal(out[0].title, '本地');
  });
});

describe('删除对账 —— 只在全量拉取时做', () => {
  interface L { id: string; updatedAt: number; title: string; synced?: boolean }
  const local = (id: string, synced?: boolean): L => ({ id, updatedAt: 100, title: '本地', synced });
  const cloud = (id: string, updatedAt = 100): CloudItem<L> => ({
    id,
    updatedAt,
    deleted: false,
    value: { id, updatedAt, title: '云端', synced: true },
  });

  test('全量：同步过的本地记录，服务端没有 → 删掉（别处删了）', () => {
    const out = reconcile([local('a', true)], [cloud('b')], new Set(), true);
    assert.equal(out.length, 1);
    assert.equal(out[0].id, 'b');
  });

  test('全量：没同步过的本地记录 → 保留（未登录时记的东西不能因登录而消失）', () => {
    const out = reconcile([local('a', false)], [cloud('b')], new Set(), true);
    assert.equal(out.length, 2);
    assert.ok(out.some(e => e.id === 'a'));
  });

  test('全量：没有 synced 标记（旧数据）→ 保守保留', () => {
    const out = reconcile([local('a', undefined)], [cloud('b')], new Set(), true);
    assert.equal(out.length, 2);
  });

  test('全量：待推送的记录不受对账影响', () => {
    const out = reconcile([local('a', true)], [cloud('b')], new Set(['a']), true);
    assert.equal(out.length, 2);
  });

  test('增量：不做对账（本地多出来的记录留着）', () => {
    const out = reconcile([local('a', true)], [cloud('b')], new Set(), false);
    assert.equal(out.length, 2);
  });
});
