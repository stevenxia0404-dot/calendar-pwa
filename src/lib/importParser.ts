// 课表导入的解析 —— 纯逻辑，可单测
//
// 三条原则（文档 10.1）：
//   1. 只认明确的列，不猜。Excel 里写了日期就用日期列，没写就留空让人补，
//      绝不从标题或备注里去推测。
//   2. 每行都能改再入库。预览页是修正的最后机会。
//   3. 认不出来的就明说。告诉用户「这一列我不认识」，而不是猜一个。
//
// 「猜」这件事为什么必须删：Excel 里写好的时间本来是对的，
// 标题里出现「3点」就把它覆盖掉，是用不确定去覆盖确定。

import { parseCsvLine } from './csv.ts';

export interface ImportDraft {
  /** 绝对日期 YYYY-MM-DD；文件里没写或格式不对则为空，等用户补 */
  date: string;
  /** 开始时间 HH:mm；没有则为空 */
  time: string;
  /** 结束时间 HH:mm */
  endTime: string;
  title: string;
  location: string;
  people: string;
  /** 原话（备注列） */
  raw: string;
  /** 有没有时间是系统看内容自己判断的，不让用户选 */
  type: 'event' | 'task';
}

const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const TIME_RE = /^\d{1,2}:\d{2}$/;

/** 归一化时间：9:5 → 09:05；不是时间就返回空 */
export function normalizeTime(v: string): string {
  const s = (v || '').trim();
  if (!TIME_RE.test(s)) return '';
  const [h, m] = s.split(':');
  const hh = parseInt(h, 10);
  const mm = parseInt(m, 10);
  if (hh > 23 || mm > 59) return '';
  return `${String(hh).padStart(2, '0')}:${String(mm).padStart(2, '0')}`;
}

/** 归一化日期：只认 YYYY-MM-DD；其它格式（2026/11/2、11月2日）不猜 */
export function normalizeDate(v: string): string {
  const s = (v || '').trim();
  return DATE_RE.test(s) ? s : '';
}

/**
 * 表头 → 列下标。
 *
 * 先找完全相等的，再找包含的。「包含」这一层必须带占用标记 ——
 * 否则「结束时间」会被「时间」这一列先抢走（因为它也包含「时间」）。
 */
export function mapColumns(header: string[]): {
  date: number; time: number; endTime: number; content: number;
  location: number; people: number; note: number;
} {
  const used = new Set<number>();
  const cells = (header || []).map(c => c.trim());

  const find = (names: string[]): number => {
    for (const k of names) {
      const i = cells.indexOf(k);
      if (i >= 0 && !used.has(i)) { used.add(i); return i; }
    }
    for (const k of names) {
      const i = cells.findIndex((c, j) => !used.has(j) && c.includes(k));
      if (i >= 0) { used.add(i); return i; }
    }
    return -1;
  };

  // 顺序要紧：结束时间先认，否则会被「时间」抢走
  const endTime = find(['结束时间']);
  const time = find(['开始时间', '时间']);
  const date = find(['日期']);
  const content = find(['内容', '事项', '日程', '标题']);
  const location = find(['地点', '位置']);
  const people = find(['人员', '参与人', '教员']);
  const note = find(['备注', '描述', '说明', '原话']);

  return { date, time, endTime, content, location, people, note };
}

/**
 * 解析文本为导入草稿。
 *
 * @param text       CSV 文本（可有可无表头）
 * @param hasHeader  第一行是不是表头
 */
export function parseImportRows(text: string, hasHeader: boolean): ImportDraft[] {
  const lines = (text || '').replace(/^﻿/, '').split('\n').map(l => l.trim()).filter(Boolean);
  if (!lines.length) return [];

  // 表头存在时按表头映射列，否则按标准七列的位置
  let idx = { date: 0, time: 1, endTime: 2, content: 3, location: 4, people: 5, note: 6 };
  let start = 0;

  if (hasHeader) {
    idx = mapColumns(parseCsvLine(lines[0]));
    start = 1;
  }

  const drafts: ImportDraft[] = [];

  for (let i = start; i < lines.length; i++) {
    const cells = parseCsvLine(lines[i]);
    const pick = (n: number) => (n >= 0 && n < cells.length ? (cells[n] || '').trim() : '');

    const date = normalizeDate(pick(idx.date));
    const time = normalizeTime(pick(idx.time));
    const endTime = normalizeTime(pick(idx.endTime));
    const content = pick(idx.content);
    const location = pick(idx.location);
    const people = pick(idx.people);
    const note = pick(idx.note);

    // 一行全空就跳过
    if (!date && !content && !time && !location && !people && !note) continue;
    // 整行没有任何可用的信息，跳过（避免导入一堆空行）
    if (!date && !content) continue;

    drafts.push({
      date,
      time,
      endTime,
      title: content || '未命名',
      location,
      people,
      raw: note || content,
      type: time ? 'event' : 'task',
    });
  }

  return drafts;
}

/**
 * 判断第一行是不是表头。
 *
 * 判据有两条，缺一不可：
 *   1. 这一行里出现了已知的列名（日期、时间、事项……）
 *   2. 第一格不是合法日期 —— 是合法日期就说明这是一条数据
 *
 * 第 2 条很关键：「2026-11-04,,,整理文档,,,」这种没有时间的数据行，
 * 里面也可能带「备注」这样的词，光看第 1 条会把它误判成表头。
 */
export function looksLikeHeader(firstLine: string): boolean {
  if (!firstLine) return false;
  const cells = parseCsvLine(firstLine);
  const names = ['日期', '时间', '事项', '内容', '地点', '人员', '备注', '结束时间', '标题', '日程'];
  const hit = cells.some(c => names.some(n => c.includes(n)));
  if (!hit) return false;
  // 第一格是合法日期 → 这是数据行，不是表头
  if (normalizeDate(cells[0] || '')) return false;
  return true;
}
