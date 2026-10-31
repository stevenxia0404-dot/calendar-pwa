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
 * 解析一行 CSV（用于读回）。
 *
 * 双引号包起来的字段里，逗号不算分隔符；两个连续的双引号表示一个引号。
 */
export function parseCsvLine(line: string): string[] {
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
    } else if (ch === ',') {
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
