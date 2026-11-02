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
//
// 「不猜」的边界在哪（这一条容易搞混）：
//   **认写法** 不算猜 ——「2026/11/20」和「2026-11-20」指的是同一天，
//   都把年份和月日写明了，没有不确定。写法宽松一点，人少填一次。
//   **认不出** 才算猜 ——「11月2日」不知道是哪一年，「下周二」不知道是哪天，
//   「下午3点」不知道几点。这些一律不认，留空让用户在预览里补。
//   所以规则是：**年份必须明确，写法可以不同。**

import { parseCsvLine, detectDelimiter } from './csv.ts';

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

// ==================== 日期与时间的解析 ====================
//
// 所有入口（xlsx 单元格、粘贴的文本、CSV 单元格）都走这一套，
// 免得出现「同一天，xlsx 里认得、粘贴时不认」这种割裂。

function pad2(n: number): string {
  return String(n).padStart(2, '0');
}

/**
 * 日期写法：年份必须明确，分隔符可以不同。
 *   2026-11-20   2026/11/20   2026/11/2   2026.11.20   2026年11月20日
 */
function parseDateParts(s: string): { y: number; m: number; d: number } | null {
  const t = s.trim();

  // 分隔符写法：年-月-日 / 年/月/日 / 年.月.日
  const a = t.match(/^(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})$/);
  if (a) return { y: +a[1], m: +a[2], d: +a[3] };

  // 中文写法：2026年11月20日
  const b = t.match(/^(\d{4})年(\d{1,2})月(\d{1,2})日$/);
  if (b) return { y: +b[1], m: +b[2], d: +b[3] };

  // 没有年份一律不认 —— 那是猜（「11月2日」是哪一年？）
  return null;
}

/** 真实存在的日期才给（2026-02-30 这种要挡掉） */
function formatDate(p: { y: number; m: number; d: number }): string {
  if (p.m < 1 || p.m > 12 || p.d < 1 || p.d > 31) return '';

  // 先用 2000 年构造再改年份 —— 直接 Date.UTC(y, ...) 会把 0~99 的年份
  // 当成 1900+year（JS 的历史包袱）。
  const dt = new Date(Date.UTC(2000, p.m - 1, p.d));
  dt.setUTCFullYear(p.y);
  if (dt.getUTCFullYear() !== p.y || dt.getUTCMonth() !== p.m - 1 || dt.getUTCDate() !== p.d) {
    return '';  // 2026-02-30 这种不存在的日期
  }

  return `${p.y}-${pad2(p.m)}-${pad2(p.d)}`;
}

/** 时间：8:50 → 08:50；25:00 这种不存在的时刻不认 */
function parseClock(s: string): string {
  const m = s.trim().match(/^(\d{1,2}):(\d{2})(?::(\d{2}))?$/);
  if (!m) return '';
  const h = +m[1];
  const mi = +m[2];
  if (h > 23 || mi > 59) return '';
  return `${pad2(h)}:${pad2(mi)}`;
}

/**
 * 把一段文本拆成「日期部分」和「时间部分」。
 *
 * 「2026/11/20 08:50」这种一个格里带日期又带时间的，
 * 拆成两半，两列各取各的 —— 值就在那格里，不该丢掉一半。
 */
function splitDateTime(s: string): { dateText: string; timeText: string } {
  const tm = s.match(/(\d{1,2}):(\d{2})(?::\d{2})?$/);
  if (tm && tm.index !== undefined) {
    // ISO 写法「2026-11-20T08:50:00」里的 T 要去掉，剩下才是日期
    const dateText = s.slice(0, tm.index).trim().replace(/T$/, '');
    return { dateText, timeText: tm[0] };
  }
  return { dateText: s.trim(), timeText: '' };
}

/** 归一化时间：9:5 → 09:05；不是时间就返回空 */
export function normalizeTime(v: string): string {
  return cellToParts(v).time;
}

/**
 * 归一化日期 → YYYY-MM-DD。
 *
 * 认：2026-11-20 / 2026/11/20 / 2026/11/2 / 2026.11.20 / 2026年11月20日
 * 不认：11月2日（没年份）、下周二（相对词）、2026-02-30（不存在的日期）
 */
export function normalizeDate(v: string): string {
  return cellToParts(v).date;
}

/** 表头 → 列下标的映射 */
export interface ColumnMap {
  date: number; time: number; endTime: number; content: number;
  location: number; people: number; note: number;
}

/**
 * 表头 → 列下标。
 *
 * 先找完全相等的，再找包含的。「包含」这一层必须带占用标记 ——
 * 否则「结束时间」会被「时间」这一列先抢走（因为它也包含「时间」）。
 */
export function mapColumns(header: string[]): ColumnMap {
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
 * @param text       CSV 文本，或从 Excel 复制来的制表符分隔文本
 * @param hasHeader  第一行是不是表头
 */
export function parseImportRows(text: string, hasHeader: boolean): ImportDraft[] {
  // 不整行 trim —— 制表符分隔的行末尾常有一个空列（备注列），
  // trim 掉末尾的制表符会把那一列吃掉，列数对不上。
  // 单元格级别的空白由 parseCsvLine 负责 trim。
  const lines = (text || '').replace(/^﻿/, '').split('\n').filter(l => l.trim());
  if (!lines.length) return [];

  // 分隔符：逗号（CSV）还是制表符（从 Excel 复制出来的）
  const delimiter = detectDelimiter(lines[0]);

  // 表头存在时按表头映射列，否则按标准七列的位置
  let idx = { date: 0, time: 1, endTime: 2, content: 3, location: 4, people: 5, note: 6 };
  let start = 0;

  if (hasHeader) {
    idx = mapColumns(parseCsvLine(lines[0], delimiter));
    start = 1;
  }

  const drafts: ImportDraft[] = [];

  for (let i = start; i < lines.length; i++) {
    const cells = parseCsvLine(lines[i], delimiter);
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

// ==================== 单元格取值（xlsx） ====================
//
// Excel 的单元格不是只有字符串。三种形态各自要当心：
//
//   1. Date 对象 —— 日期单元格和「纯时间」单元格都是它，含义却完全不同：
//        日期：2026-11-20T00:00:00Z
//        时间：1899-12-30T08:50:00Z   ← 日期部分只是 Excel 的纪元哨兵
//      同一个类型，认错就会把「8:50」导成一个 1899 年的日期。
//
//   2. 字符串 —— 用户把列设成「文本」时的原样值。
//
//   3. 数字 —— 格式没被识别成日期时的序列号（比如公式 =TIME(8,50,0)）。
//
// 所以这里不按「一个格子 = 一段文本」处理，而是按**列的角色**拆出日期和时间。

/**
 * Excel 纪元哨兵的年份上限。
 * 纯时间单元格的日期部分落在 1899-12-30（1900 制）或 1904-01-01（1904 制），
 * 都不是真实日期。这个值以内的年份一律当作「只有时间」。
 */
const EXCEL_EPOCH_YEAR_MAX = 1904;

/** 一个单元格里能拆出来的日期与时间 */
export interface CellParts {
  /** YYYY-MM-DD；不是日期则为空 */
  date: string;
  /** HH:mm；没有时间则为空 */
  time: string;
}

const EMPTY_PARTS: CellParts = { date: '', time: '' };

/**
 * 把一个单元格拆成日期与时间两部分。
 *
 * 与 normalizeDate / normalizeTime 是同一套规则（它们就是调用本函数），
 * 所以 xlsx 路径和文本路径不会给出不同答案。
 */
export function cellToParts(c: unknown): CellParts {
  if (c === null || c === undefined) return EMPTY_PARTS;

  // 1. Date：日期与时间都在里面，要分开拿
  if (c instanceof Date) {
    const y = c.getUTCFullYear();
    const m = String(c.getUTCMonth() + 1).padStart(2, '0');
    const d = String(c.getUTCDate()).padStart(2, '0');
    const hh = String(c.getUTCHours()).padStart(2, '0');
    const mi = String(c.getUTCMinutes()).padStart(2, '0');

    // 日期部分在纪元哨兵范围内 → 这是「纯时间」单元格，不是日期
    const realDate = y > EXCEL_EPOCH_YEAR_MAX ? `${y}-${m}-${d}` : '';

    // 时钟全是 0 → 只有日期没有时间。
    // 不然「2026/11/20」这个纯日期会被当成「零点的事」，
    // 记录就从「没时间的」变成「半夜零点的一条」，性质悄悄变了。
    const hasClock = hh !== '00' || mi !== '00';

    return { date: realDate, time: hasClock ? `${hh}:${mi}` : '' };
  }

  // 2. 字符串
  if (typeof c === 'string') {
    const s = c.trim();
    if (!s) return EMPTY_PARTS;

    // 一个格里可能同时有日期和时间（「2026/11/20 08:50」），拆成两半
    const { dateText, timeText } = splitDateTime(s);
    const dp = parseDateParts(dateText);
    const t = parseClock(timeText);
    return {
      date: dp ? formatDate(dp) : '',
      time: t,
    };
  }

  // 3. 数字（Excel 序列号）
  if (typeof c === 'number') {
    // 0 ≤ v < 1 → 一天里的小数部分 = 纯时间（如 =TIME(8,50,0)）
    if (c >= 0 && c < 1) {
      const totalMin = Math.round(c * 24 * 60);
      const hh = Math.floor(totalMin / 60) % 24;
      const mi = totalMin % 60;
      return { date: '', time: `${String(hh).padStart(2, '0')}:${String(mi).padStart(2, '0')}` };
    }
    // ≥ 1 的数字分不清是日期序列号还是普通数字，不猜。
    return EMPTY_PARTS;
  }

  return EMPTY_PARTS;
}

/**
 * 单元格值转文本（不区分日期与时间）。
 *
 * Excel 里的「真日期」是日期序列号，解析出来是 Date 对象，
 * 直接 String() 会得到 "Mon Nov 02 2026 ..." 这种乱码，导入必失败。
 */
export function cellToText(c: unknown): string {
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

/**
 * 把一行 xlsx 单元格转成模板的七列文本。
 *
 * 顺序固定：日期,开始时间,结束时间,事项,地点,人员,备注
 *
 * 日期列和时间列走 cellToParts（Excel 的「纯时间」单元格也是 Date 对象，
 * 按文本拍平会把时间整个丢掉）；其余列走 cellToText。
 */
export function xlsxRowToTemplateCells(row: unknown[], idx: ColumnMap): string[] {
  const cells = row.map(c => cellToText(c).trim());
  const pick = (i: number) => (i >= 0 && i < cells.length ? cells[i] : '');
  const pickPart = (i: number) =>
    (i >= 0 && i < row.length ? cellToParts(row[i]) : { date: '', time: '' });

  const datePart = pickPart(idx.date);
  const timePart = pickPart(idx.time);
  const endPart = pickPart(idx.endTime);

  const date = datePart.date;
  let time = timePart.time;
  const endTime = endPart.time;

  // 一个单元格里同时带日期和时间（「2026/11/20 8:50」），
  // 而时间列空着 —— 就用同一个单元格里带着的时间。
  // 这不是猜：值就在那个单元格里，只是被并进了一列。
  if (!time && datePart.time) time = datePart.time;

  return [date, time, endTime, pick(idx.content), pick(idx.location), pick(idx.people), pick(idx.note)];
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
  const cells = parseCsvLine(firstLine, detectDelimiter(firstLine));
  const names = ['日期', '时间', '事项', '内容', '地点', '人员', '备注', '结束时间', '标题', '日程'];
  const hit = cells.some(c => names.some(n => c.includes(n)));
  if (!hit) return false;
  // 第一格是合法日期 → 这是数据行，不是表头
  if (normalizeDate(cells[0] || '')) return false;
  return true;
}
