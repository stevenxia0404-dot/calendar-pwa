// CSV 原语 —— 导入与导出共用一套
//
// 为什么要共用：导入要能解析，导出要能生成。两边对「字段里含逗号和引号
// 怎么办」的规则必须完全一致，否则会出现「导出的文件自己读不回来」。
//
// 规则是 Excel 的那套：
//   含逗号、引号、换行的字段用双引号包起来
//   字段里的双引号写成两个

/** 字段转义（用于生成 CSV） */
export function escapeCsvField(value: string): string {
  const v = value ?? '';
  if (/[",\n\r]/.test(v)) {
    return '"' + v.replace(/"/g, '""') + '"';
  }
  return v;
}

/**
 * 判断一行用的是什么分隔符。
 *
 * 数引号外的逗号和制表符，谁多算谁的。
 *
 * 为什么要有这个：从 Excel 里复制一段区域到剪贴板，粘出来是
 * **制表符**分隔的（不是逗号）。不判断的话整行会被当成一格，
 * 后面所有列全部对不上 —— 而且不报错，只是「未识别到有效数据」。
 *
 * 顺带一提，Excel 复制时对含制表符/换行/引号的单元格也是用双引号包起来、
 * 内部引号写两遍，跟 CSV 一套规矩，所以能共用同一个解析器。
 */
export function detectDelimiter(line: string): string {
  let commas = 0;
  let tabs = 0;
  let inQuote = false;

  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      // 一对双引号是转义，跳过
      if (inQuote && line[i + 1] === '"') { i++; continue; }
      inQuote = !inQuote;
      continue;
    }
    if (inQuote) continue;
    if (ch === ',') commas++;
    else if (ch === '\t') tabs++;
  }

  return tabs > commas ? '\t' : ',';
}

/**
 * 解析一行（默认逗号分隔；Excel 复制过来的是制表符分隔）。
 *
 * 双引号包起来的字段里，分隔符不算分隔符；两个连续的双引号表示一个引号。
 */
export function parseCsvLine(line: string, delimiter = ','): string[] {
  const cells: string[] = [];
  let cur = '';
  let inQuote = false;

  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (inQuote) {
      if (ch === '"') {
        if (line[i + 1] === '"') { cur += '"'; i++; }
        else inQuote = false;
      } else {
        cur += ch;
      }
    } else if (ch === '"') {
      inQuote = true;
    } else if (ch === delimiter) {
      cells.push(cur.trim());
      cur = '';
    } else {
      cur += ch;
    }
  }
  cells.push(cur.trim());
  return cells;
}

/** 把一行数组生成 CSV（用于生成） */
export function toCsvLine(cells: string[]): string {
  return cells.map(escapeCsvField).join(',');
}
