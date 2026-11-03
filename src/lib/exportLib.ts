// 范围导出 —— v4.0
//
// 用途只有一个：把一段时间里的事导出来，自己拿去写周报或交差。
// 所以导出的内容是「日期 + 事」，不掺任何界面上的分类概念。
//
// 三档格式内容一致，只是用途不同：
//   文本  贴邮件、写周报
//   CSV   用 Excel / Numbers 打开继续加工
//   XLSX  直接是表格，发给同事
//
// 固定八列：日期、开始时间、结束时间、事项、地点、人员、原话、结束日期。
// 不带完成状态 —— 界面已经不暴露这个概念，导出是拿去做周报原料的，
// 不是用来对账的。
//
// 「结束日期」加在**末尾**而不是紧跟日期：
// 前七列的位置一个字没动，用户现有的表格、脚本、习惯都不受影响，
// 老文件（七列）也照样能导进来。

export type ExportRange = 'today' | 'week' | 'month' | 'custom';

export const EXPORT_COLUMNS = ['日期', '开始时间', '结束时间', '事项', '地点', '人员', '原话', '结束日期'];

export interface ExportRow {
  date: string;
  time: string;
  endTime: string;
  title: string;
  location: string;
  people: string;
  raw: string;
  /** 跨日事件的结束日期（含当天）；空 = 不跨日 */
  endDate: string;
}

/** 把内部记录转成导出行（只取七列，不含完成状态与内部类型） */
export function toExportRow(e: {
  date: string; time: string; endTime: string; title: string;
  location: string; people: string; raw: string; endDate?: string;
}): ExportRow {
  return {
    date: e.date,
    time: e.time || '',
    endTime: e.endTime || '',
    title: e.title,
    location: e.location || '',
    people: e.people || '',
    raw: e.raw || '',
    endDate: e.endDate || '',
  };
}

/** 按日期排序 */
export function sortRows(rows: ExportRow[]): ExportRow[] {
  return [...rows].sort((a, b) => {
    if (a.date !== b.date) return a.date.localeCompare(b.date);
    // 同一天：有时间的按时间在前，没时间的按标题排
    if (a.time && b.time) return a.time.localeCompare(b.time);
    if (a.time) return -1;
    if (b.time) return 1;
    return a.title.localeCompare(b.title);
  });
}

/** 取某天所在周的起止（周一为一周之首） */
export function weekBounds(today: Date): { from: string; to: string } {
  const d = new Date(today.getFullYear(), today.getMonth(), today.getDate());
  const dow = (d.getDay() + 6) % 7;
  d.setDate(d.getDate() - dow);
  const from = toDateString(d);
  const end = new Date(d);
  end.setDate(d.getDate() + 6);
  return { from, to: toDateString(end) };
}

/** 取某天所在月的起止 */
export function monthBounds(today: Date): { from: string; to: string } {
  const from = toDateString(new Date(today.getFullYear(), today.getMonth(), 1));
  const to = toDateString(new Date(today.getFullYear(), today.getMonth() + 1, 0));
  return { from, to };
}

export function toDateString(d: Date): string {
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${y}-${m}-${day}`;
}

/**
 * 按范围筛选。
 *
 * @param rows   全部记录
 * @param range  今天 / 本周 / 本月 / 自定义
 * @param today  今天（可注入，便于测试）
 * @param custom 自定义区间的起止（YYYY-MM-DD）
 */
export function filterByRange(
  rows: ExportRow[],
  range: ExportRange,
  today: Date,
  custom?: { from: string; to: string },
): ExportRow[] {
  let from: string;
  let to: string;

  if (range === 'today') {
    from = to = toDateString(today);
  } else if (range === 'week') {
    ({ from, to } = weekBounds(today));
  } else if (range === 'month') {
    ({ from, to } = monthBounds(today));
  } else {
    from = custom?.from || '';
    to = custom?.to || '';
  }

  return sortRows(rows.filter(r => r.date >= from && r.date <= to));
}

/** 导出矩阵：首行是表头 */
export function toMatrix(rows: ExportRow[]): string[][] {
  return [
    [...EXPORT_COLUMNS],
    ...rows.map(r => [r.date, r.time, r.endTime, r.title, r.location, r.people, r.raw, r.endDate]),
  ];
}

// CSV 转义规则与导入共用一套 —— 导出的文件必须能被自己读回来。
// 字段含逗号、引号或换行时用双引号包起来，字段内的双引号写成两个。
import { escapeCsvField } from './csv.ts';
export { escapeCsvField };

/** 生成 CSV 文本（带 UTF-8 BOM，Excel 打开中文不乱码） */
export function toCsv(rows: ExportRow[]): string {
  const matrix = toMatrix(rows);
  return '﻿' + matrix.map(line => line.map(escapeCsvField).join(',')).join('\r\n');
}

/**
 * 生成纯文本：按天分组，一天一个小节。
 * 写周报时最顺手的形式 —— 照着往下编就行。
 */
export function toText(rows: ExportRow[]): string {
  if (!rows.length) return '（这个区间没有记录）';

  const byDate = new Map<string, ExportRow[]>();
  for (const r of rows) {
    const list = byDate.get(r.date) || [];
    list.push(r);
    byDate.set(r.date, list);
  }

  const out: string[] = [];
  byDate.forEach((list, date) => {
    const d = new Date(date + 'T00:00:00');
    const week = '日一二三四五六'[d.getDay()];
    out.push(`${date}（周${week}）`);

    for (const r of list) {
      const time = r.time ? (r.endTime ? `${r.time}-${r.endTime}` : r.time) : '';
      const extra = [r.location, r.people].filter(Boolean).join(' · ');
      const head = time ? `${time}  ${r.title}` : r.title;
      out.push(extra ? `  ${head}（${extra}）` : `  ${head}`);
    }
    out.push('');
  });
  return out.join('\n');
}

/** 导出文件名：日程_2026-10-31_本周 */
export function exportFileName(range: ExportRange, label: string, today: Date): string {
  const rangeLabel = { today: '今天', week: '本周', month: '本月', custom: '自定义' }[range];
  return `日程_${toDateString(today)}_${label || rangeLabel}`;
}
