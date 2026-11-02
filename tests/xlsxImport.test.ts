// 真 xlsx 的导入链路测试
//
// 为什么单独一个文件：之前「Excel 里亲手敲的时间导不进来」这个 bug
// 存在了好几个月没被发现 —— 因为所有测试都只喂纯文本，
// 从来没有真的让 Excel 格式的单元格走过一遍。
//
// 这里造一个真 xlsx：日期列是「数字 + 日期格式」，时间列是「数字 + h:mm 格式」，
// 这正是 Excel 里敲 8:50 之后存下来的样子。然后用项目真正用的那个解析库读回来，
// 走完整条导入链路，逐格断言。
//
// 单测里用假的 Date 对象只能证明「我们的函数对」；
// 这里能证明「Excel 的文件真的能被我们读对」。

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readSheet } from 'read-excel-file/node';
import {
  mapColumns,
  cellToParts,
  xlsxRowToTemplateCells,
  parseImportRows,
  looksLikeHeader,
  normalizeTime,
} from '../src/lib/importParser.ts';
import { toCsvLine } from '../src/lib/csv.ts';

// ==================== 最小 xlsx 写入器 ====================
//
// 只为造测试文件。生产用的 xlsxWriter 全写 inlineStr（字符串），
// 复现不了「Excel 真时间值」这个场景，所以这里另造一个带数字格式的。

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    t[i] = c >>> 0;
  }
  return t;
})();

function crc32(bytes: Uint8Array): number {
  let c = 0xFFFFFFFF;
  for (let i = 0; i < bytes.length; i++) c = CRC_TABLE[(c ^ bytes[i]) & 0xFF] ^ (c >>> 8);
  return (c ^ 0xFFFFFFFF) >>> 0;
}

function buildZip(entries: { name: string; data: Uint8Array }[]): Uint8Array {
  const enc = new TextEncoder();
  const parts: Uint8Array[] = [];
  const central: Uint8Array[] = [];
  let offset = 0;
  const dosTime = 0, dosDate = 0x2821;

  for (const e of entries) {
    const nameBytes = enc.encode(e.name);
    const crc = crc32(e.data);
    const size = e.data.length;

    const local = new Uint8Array(30 + nameBytes.length);
    const lv = new DataView(local.buffer);
    lv.setUint32(0, 0x04034b50, true); lv.setUint16(4, 20, true); lv.setUint16(6, 0, true);
    lv.setUint16(8, 0, true); lv.setUint16(10, dosTime, true); lv.setUint16(12, dosDate, true);
    lv.setUint32(14, crc, true); lv.setUint32(18, size, true); lv.setUint32(22, size, true);
    lv.setUint16(26, nameBytes.length, true); lv.setUint16(28, 0, true);
    local.set(nameBytes, 30);
    parts.push(local, e.data);

    const cd = new Uint8Array(46 + nameBytes.length);
    const cv = new DataView(cd.buffer);
    cv.setUint32(0, 0x02014b50, true); cv.setUint16(4, 20, true); cv.setUint16(6, 20, true);
    cv.setUint16(8, 0, true); cv.setUint16(10, 0, true); cv.setUint16(12, dosTime, true);
    cv.setUint16(14, dosDate, true); cv.setUint32(16, crc, true); cv.setUint32(20, size, true);
    cv.setUint32(24, size, true); cv.setUint16(28, nameBytes.length, true); cv.setUint16(30, 0, true);
    cv.setUint16(32, 0, true); cv.setUint16(34, 0, true); cv.setUint16(36, 0, true);
    cv.setUint32(38, 0, true); cv.setUint32(42, offset, true);
    cd.set(nameBytes, 46);
    central.push(cd);

    offset += local.length + size;
  }

  const cdSize = central.reduce((n, c) => n + c.length, 0);
  const eocd = new Uint8Array(22);
  const ev = new DataView(eocd.buffer);
  ev.setUint32(0, 0x06054b50, true); ev.setUint16(4, 0, true); ev.setUint16(6, 0, true);
  ev.setUint16(8, entries.length, true); ev.setUint16(10, entries.length, true);
  ev.setUint32(12, cdSize, true); ev.setUint32(16, offset, true); ev.setUint16(20, 0, true);

  const out = new Uint8Array(offset + cdSize + eocd.length);
  let p = 0;
  for (const c of [...parts, ...central, eocd]) { out.set(c, p); p += c.length; }
  return out;
}

function xmlEscape(s: string): string {
  return (s ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&apos;')
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, '');
}

function colName(index: number): string {
  let n = index + 1, s = '';
  while (n > 0) { const rem = (n - 1) % 26; s = String.fromCharCode(65 + rem) + s; n = Math.floor((n - 1) / 26); }
  return s;
}

/** Excel 日期序列号（1900 制），1899-12-30 = 0 */
function dateSerial(y: number, m: number, d: number): number {
  return Math.round((Date.UTC(y, m - 1, d) - Date.UTC(1899, 11, 30)) / 86400000);
}

/** Excel 时间序列号：一天里的小数部分 */
function timeSerial(h: number, min: number): number {
  return (h * 60 + min) / (24 * 60);
}

const STYLE_DATE = 1;  // numFmtId 14
const STYLE_TIME = 2;  // numFmtId 20 (h:mm)

type Cell = string | { v: number; s?: number } | null;

function cellXml(c: Cell, ref: string): string {
  if (c === null || c === undefined || c === '') return `<c r="${ref}"/>`;
  if (typeof c === 'string') {
    return `<c r="${ref}" t="inlineStr"><is><t xml:space="preserve">${xmlEscape(c)}</t></is></c>`;
  }
  const s = c.s !== undefined ? ` s="${c.s}"` : '';
  return `<c r="${ref}"${s}><v>${c.v}</v></c>`;
}

/** 造一个带数字格式的 xlsx，返回文件路径 */
function makeXlsx(rows: Cell[][]): string {
  const sheet = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n`
    + `<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>`
    + rows.map((row, r) => `<row r="${r + 1}">${row.map((c, ci) => cellXml(c, `${colName(ci)}${r + 1}`)).join('')}</row>`).join('')
    + `</sheetData></worksheet>`;

  const styles = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n`
    + `<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">`
    + `<numFmts count="0"/>`
    + `<fonts count="1"><font><sz val="11"/><name val="Calibri"/></font></fonts>`
    + `<fills count="1"><fill><patternFill patternType="none"/></fill></fills>`
    + `<borders count="1"><border/></borders>`
    + `<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>`
    + `<cellXfs count="3">`
    + `<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>`
    + `<xf numFmtId="14" fontId="0" fillId="0" borderId="0" xfId="0" applyNumberFormat="1"/>`
    + `<xf numFmtId="20" fontId="0" fillId="0" borderId="0" xfId="0" applyNumberFormat="1"/>`
    + `</cellXfs>`
    + `<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>`
    + `</styleSheet>`;

  const contentTypes = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n`
    + `<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">`
    + `<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>`
    + `<Default Extension="xml" ContentType="application/xml"/>`
    + `<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>`
    + `<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>`
    + `<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>`
    + `</Types>`;

  const rootRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n`
    + `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">`
    + `<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>`
    + `</Relationships>`;

  const workbookRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n`
    + `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">`
    + `<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>`
    + `<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>`
    + `</Relationships>`;

  const workbook = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n`
    + `<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">`
    + `<sheets><sheet name="课表" sheetId="1" r:id="rId1"/></sheets></workbook>`;

  const enc = new TextEncoder();
  const zip = buildZip([
    { name: '[Content_Types].xml', data: enc.encode(contentTypes) },
    { name: '_rels/.rels', data: enc.encode(rootRels) },
    { name: 'xl/workbook.xml', data: enc.encode(workbook) },
    { name: 'xl/_rels/workbook.xml.rels', data: enc.encode(workbookRels) },
    { name: 'xl/styles.xml', data: enc.encode(styles) },
    { name: 'xl/worksheets/sheet1.xml', data: enc.encode(sheet) },
  ]);

  const path = join(mkdtempSync(join(tmpdir(), 'xlsx-fixture-')), '课表.xlsx');
  writeFileSync(path, Buffer.from(zip));
  return path;
}

// ==================== 测试 ====================

describe('真 xlsx：Excel 里敲的时间能进来', () => {
  // 用户那张表的原样：
  //   日期 | 开始时间 | 结束时间 | 事项 | 地点 | 人员 | 备注
  const rows: Cell[][] = [
    ['日期', '开始时间', '结束时间', '事项', '地点', '人员', '备注'],
    [
      { v: dateSerial(2026, 11, 20), s: STYLE_DATE },
      { v: timeSerial(8, 50), s: STYLE_TIME },
      { v: timeSerial(10, 30), s: STYLE_TIME },
      '初始训练-模拟航班', '青浦B777经济舱', '张教员', '',
    ],
    [
      { v: dateSerial(2026, 11, 21), s: STYLE_DATE },
      { v: timeSerial(12, 50), s: STYLE_TIME },
      { v: timeSerial(13, 50), s: STYLE_TIME },
      '团队周会', 'C楼201', '全组', '',
    ],
    [
      { v: dateSerial(2026, 11, 22), s: STYLE_DATE },
      '', '', '整理文档', '', '', '培训材料归档',
    ],
  ];

  test('解析库把 Excel 的时间格读成 Date（不是文本）', async () => {
    const path = makeXlsx(rows);
    const sheet = await readSheet(path);
    assert.ok(sheet[1][0] instanceof Date, '日期格应是 Date');
    assert.ok(sheet[1][1] instanceof Date, '时间格也应是 Date —— 这就是坑的根');
    // 时间格的日期部分是 Excel 纪元哨兵，时间在 UTC 时分里
    assert.equal(sheet[1][1].getUTCHours(), 8);
    assert.equal(sheet[1][1].getUTCMinutes(), 50);
  });

  test('纪元哨兵不会被当成日期导进去', async () => {
    const path = makeXlsx(rows);
    const sheet = await readSheet(path);
    const p = cellToParts(sheet[1][1]);
    assert.equal(p.time, '08:50');
    assert.equal(p.date, '');
  });

  test('整张表：日期时间地点人员全部对上', async () => {
    const path = makeXlsx(rows);
    const sheet = await readSheet(path);
    const header = sheet[0].map(c => String(c));
    const idx = mapColumns(header);
    const out = sheet.slice(1).map(r => xlsxRowToTemplateCells(r, idx));

    assert.deepEqual(out[0], ['2026-11-20', '08:50', '10:30', '初始训练-模拟航班', '青浦B777经济舱', '张教员', '']);
    assert.deepEqual(out[1], ['2026-11-21', '12:50', '13:50', '团队周会', 'C楼201', '全组', '']);
    assert.deepEqual(out[2], ['2026-11-22', '', '', '整理文档', '', '', '培训材料归档']);
  });

  test('走完整条链路后，时间还在、类型也没被降级', async () => {
    const path = makeXlsx(rows);
    const sheet = await readSheet(path);
    const header = sheet[0].map(c => String(c));
    const idx = mapColumns(header);
    const csv = ['日期,开始时间,结束时间,事项,地点,人员,备注',
      ...sheet.slice(1).map(r => toCsvLine(xlsxRowToTemplateCells(r, idx)))].join('\n');

    const drafts = parseImportRows(csv, looksLikeHeader(csv.split('\n')[0]));
    assert.equal(drafts.length, 3);
    assert.equal(drafts[0].date, '2026-11-20');
    assert.equal(drafts[0].time, '08:50');
    assert.equal(drafts[0].endTime, '10:30');
    // 关键：有时间就该是带时间轴的事，不能被静默降级成「没时间的」
    assert.equal(drafts[0].type, 'event');
    assert.equal(drafts[1].time, '12:50');
    // 本来就没时间的那行，仍然是没时间
    assert.equal(drafts[2].time, '');
    assert.equal(drafts[2].type, 'task');
  });

  test('回归锁：老逻辑会把时间变成 1899 年的假日期', async () => {
    // 这条断言的是「坑长什么样」——
    // 以后谁再把 Date 一律拍成 YYYY-MM-DD，这条会红。
    const path = makeXlsx(rows);
    const sheet = await readSheet(path);
    const idx = mapColumns(sheet[0].map(c => String(c)));

    // 老逻辑：不管什么列，Date 一律拍成 YYYY-MM-DD
    const oldWay = (c: unknown) => {
      if (c instanceof Date) {
        const y = c.getUTCFullYear();
        const m = String(c.getUTCMonth() + 1).padStart(2, '0');
        const d = String(c.getUTCDate()).padStart(2, '0');
        return `${y}-${m}-${d}`;
      }
      return String(c ?? '');
    };

    const oldTime = oldWay(sheet[1][idx.time]);
    assert.equal(oldTime, '1899-12-30', '老逻辑确实把时间变成了假日期');
    assert.equal(normalizeTime(oldTime), '', '这个假日期过不了时间校验 → 时间丢失');
  });
});
