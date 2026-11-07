// 规则解析模块 —— 把一句自然语言解析成「日期 + 时间 + 干净描述」
//
// 设计原则（v4.0 文档第四章、第八章）
//
// 1. 封闭集合。日期表达只认一组明确枚举，不做开放式语义理解。
//    「过两天」「月底」「下个月吧」不在集合内 → 判为解不出。
//
// 2. 必须可修正，而非必须成功。
//    解不出时落今天 + date_confirmed=0 + 原话保留，由用户扫一眼改掉。
//    这比「猜一个日期」安全：显性的降级不会骗人，隐性的错误会。
//
// 3. 相对词用完即弃。算出绝对日期后，句首的日期锚点词从描述里剥离，
//    不进数据库、不进界面。日期是「事情发生的那一天」这个事实，落库即绝对值。
//
// 4. 描述与时间分工。
//    日期锚点（今天/明天/上周三…）→ 只参与日期计算，剥离。
//    时段词（上午/下午/晚上/中午…）→ 能与钟点组合则转成时间并剥离；
//      单独出现则保留在描述里（那是有效信息，不是歧义）。
//    句中的日期词 → 保留。它指的不是「记录在哪天」，是内容的一部分。
//
// 5. 无 AI、无网络、无外部依赖。纯函数，输入输出确定，可完整单测。

// ==================== 类型 ====================

export interface ParsedResult {
  /** 绝对日期 YYYY-MM-DD，永远存在（解不出时为基准日） */
  date: string;
  /** HH:mm，空串表示无时间 */
  time: string;
  /** 跨日事件的结束日期 YYYY-MM-DD（含当天）；空串 = 不跨日 */
  endDate: string;
  /** 剥离日期锚点后的干净描述 */
  title: string;
  /** 原话全文，永不丢 */
  raw: string;
  /** 0 = 规则没解出日期，待用户确认；1 = 已确认 */
  dateConfirmed: 0 | 1;
  /** 解出的日期锚点词，仅用于调试与「待确认」提示，不入界面 */
  matchedAnchor: string | null;
}

// ==================== 基准日 ====================

/** 把 Date 规整成本地时区的 YYYY-MM-DD */
export function toDateString(d: Date): string {
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${y}-${m}-${day}`;
}

function addDays(base: Date, n: number): Date {
  const d = new Date(base.getFullYear(), base.getMonth(), base.getDate());
  d.setDate(d.getDate() + n);
  return d;
}

/** 周一为一周之首（与日历一致） */
function startOfWeek(base: Date): Date {
  const d = new Date(base.getFullYear(), base.getMonth(), base.getDate());
  const dow = (d.getDay() + 6) % 7; // 周一=0
  d.setDate(d.getDate() - dow);
  return d;
}

// ==================== 词表 ====================

const WEEKDAY_CN: Record<string, number> = {
  一: 0, 二: 1, 三: 2, 四: 3, 五: 4, 六: 5, 日: 6, 天: 6,
};

/** 时段词 → 对应的钟点区间。null 表示无法确定具体钟点。 */
const PERIOD_TIMES: { words: string[]; hour: number | null }[] = [
  { words: ['凌晨'], hour: 5 },
  { words: ['早上', '早晨', '清晨'], hour: 8 },
  { words: ['上午'], hour: 10 },
  { words: ['中午'], hour: 12 },
  { words: ['下午'], hour: 15 },
  { words: ['傍晚'], hour: 18 },
  { words: ['晚上', '夜里', '夜晚'], hour: 20 },
  { words: ['半夜'], hour: 23 },
];

/** 中文数字 → 阿拉伯数字（覆盖 0~99，够时刻与日期用） */
const CN_DIGITS: Record<string, number> = {
  零: 0, 〇: 0, 一: 1, 二: 2, 两: 2, 三: 3, 四: 4, 五: 5,
  六: 6, 七: 7, 八: 8, 九: 9, 十: 10,
};

function cnNumberToInt(s: string): number | null {
  if (!s) return null;
  // 纯阿拉伯数字
  if (/^\d+$/.test(s)) return parseInt(s, 10);
  // 十位：十/十二/二十…
  if (s.includes('十')) {
    const [tens, ones] = s.split('十');
    const t = tens === '' ? 1 : (CN_DIGITS[tens] ?? null);
    const o = ones === '' ? 0 : (CN_DIGITS[ones] ?? null);
    if (t === null || o === null) return null;
    return t * 10 + o;
  }
  // 单个数字
  if (s.length === 1) return CN_DIGITS[s] ?? null;
  return null;
}

/** 把一段数字文本转成数字，支持阿拉伯与中文 */
function parseNumber(s: string): number | null {
  return cnNumberToInt(s.replace(/[^\d零〇一二两三四五六七八九十]/g, ''));
}

// ==================== 日期锚点匹配 ====================
//
// 顺序很重要：先匹配更长的、更具体的表达。
// 例如「下周五」必须先于「周五」匹配，「3天后」先于「后」。
//
// 每条规则返回：匹配到的文本、算出的日期、以及该匹配在句中的位置。

interface AnchorRule {
  regex: RegExp;
  /** 计算目标日期；未匹配返回 null */
  resolve: (m: RegExpMatchArray, base: Date) => string | null;
  /** 该规则产出的日期是否需要从描述里剥离 */
  strip: boolean;
}

const DAY_OFFSETS: Record<string, number> = {
  今天: 0, 今日: 0, 本日: 0,
  明天: 1, 明日: 1,
  后天: 2,
  昨天: -1, 昨日: -1,
  前天: -2,
  大后天: 3,
  大前天: -3,
};

const ANCHOR_RULES: AnchorRule[] = [
  // —— N天后 / N天前 ——
  {
    regex: /([0-9零〇一二两三四五六七八九十]+)\s*天\s*(后|后头|以后)/,
    resolve: (m, base) => {
      const n = parseNumber(m[1]);
      if (n === null) return null;
      return toDateString(addDays(base, n));
    },
    strip: true,
  },
  {
    regex: /([0-9零〇一二两三四五六七八九十]+)\s*天\s*(前|以前|之前)/,
    resolve: (m, base) => {
      const n = parseNumber(m[1]);
      if (n === null) return null;
      return toDateString(addDays(base, -n));
    },
    strip: true,
  },
  // —— 上周X / 本周X / 下周X ——
  {
    regex: /(上|这|本|下)\s*周\s*([一二三四五六日天])/,
    resolve: (m, base) => {
      const offset = m[1] === '上' ? -1 : m[1] === '下' ? 1 : 0;
      const target = WEEKDAY_CN[m[2]];
      if (target === undefined) return null;
      const weekStart = startOfWeek(base);
      // 本周X：若目标日已过，仍在本周内（过去的那天）
      return toDateString(addDays(weekStart, offset * 7 + target));
    },
    strip: true,
  },
  // —— 上个月X号 / 下个月X号 ——
  {
    regex: /(上|下)\s*个?月\s*([0-9零〇一二两三四五六七八九十]+)\s*[号日]/,
    resolve: (m, base) => {
      const n = parseNumber(m[2]);
      if (n === null || n < 1 || n > 31) return null;
      const monthDelta = m[1] === '上' ? -1 : 1;
      const d = new Date(base.getFullYear(), base.getMonth() + monthDelta, n);
      return toDateString(d);
    },
    strip: true,
  },
  // —— X月X号 / X月X日 ——
  {
    regex: /([0-9]{1,2})\s*月\s*([0-9]{1,2})\s*[号日]/,
    resolve: (m, base) => {
      const month = parseInt(m[1], 10);
      const day = parseInt(m[2], 10);
      if (month < 1 || month > 12 || day < 1 || day > 31) return null;
      let d = new Date(base.getFullYear(), month - 1, day);
      // 已过的日期算明年（与用例「10月5号交表 → 2027-10-05」一致）
      if (d.getTime() < base.getTime()) d = new Date(base.getFullYear() + 1, month - 1, day);
      return toDateString(d);
    },
    strip: true,
  },
  // —— X/X ——
  {
    regex: /([0-9]{1,2})\s*\/\s*([0-9]{1,2})/,
    resolve: (m, base) => {
      const month = parseInt(m[1], 10);
      const day = parseInt(m[2], 10);
      if (month < 1 || month > 12 || day < 1 || day > 31) return null;
      let d = new Date(base.getFullYear(), month - 1, day);
      if (d.getTime() < base.getTime()) d = new Date(base.getFullYear() + 1, month - 1, day);
      return toDateString(d);
    },
    strip: true,
  },
  // —— 今天 / 明天 / 后天 … ——
  {
    regex: /(大前天|大后天|今天|今日|本日|明天|明日|后天|昨天|昨日|前天)/,
    resolve: (m, base) => {
      const off = DAY_OFFSETS[m[1]];
      if (off === undefined) return null;
      return toDateString(addDays(base, off));
    },
    strip: true,
  },
];

// ==================== 时间匹配 ====================

interface TimeMatch {
  time: string;
  /** 该时间表达在原句中的起止位置 */
  start: number;
  end: number;
  /** 匹配到的原始文本 */
  text: string;
}

/** 匹配「下午3点」「15:30」「晚上八点」「3点半」这类时刻 */
function matchTime(text: string): TimeMatch | null {
  // 每个模式**显式标出种类**。
  //
  // 为什么不能靠 `p.source.includes(':')` 判断：
  // 那是个脆弱的特征匹配 —— 只要正则里出现任何非捕获组 `(?:`，
  // source 里就带一个冒号，会被误判成「数字 HH:mm 模式」。
  // 踩过：给中文分钟加了个 `(?:\s*(...)\s*分?)?`，
  // 结果 parseInt('下午') = NaN，时间变成 'NaN:03'。
  const patterns: { re: RegExp; kind: 'cn' | 'hhmm' }[] = [
    {
      // 下午3点 / 晚上八点 / 上午9点半 / 3点
      // 下午三点五十分 / 三点二十 / 三点零五分 / 三点一刻
      //
      // 分钟的写法有两种，都得认：
      //   「半 / 正 / 整 / 一刻 / 三刻」—— 固定说法
      //   「五十 / 二十 / 五」+ 可选的「分」—— 中文数字，后面那个「分」字
      //     语音识别时经常丢（说「三点五十」可能不给「分」），
      //     所以「分」做成可选；但数字部分限 1~3 位，避免把后面的内容吃进来。
      kind: 'cn',
      re: /(凌晨|早上|早晨|清晨|上午|中午|下午|傍晚|晚上|夜里|夜晚|半夜)?\s*([0-9零〇一二两三四五六七八九十]{1,3})\s*[点時时]\s*(半|正|整|一刻|三刻)?(?:\s*([0-9零〇一二两三四五六七八九十]{1,3})\s*分?)?/,
    },
    {
      // 15:30 / 9:00
      kind: 'hhmm',
      re: /([0-9]{1,2})\s*[:：]\s*([0-9]{2})/,
    },
  ];

  for (const { re, kind } of patterns) {
    const m = text.match(re);
    if (!m || m.index === undefined) continue;

    if (kind === 'hhmm') {
      // HH:mm
      const h = parseInt(m[1], 10);
      const min = parseInt(m[2], 10);
      if (h > 23 || min > 59) continue;
      return {
        time: `${String(h).padStart(2, '0')}:${String(min).padStart(2, '0')}`,
        start: m.index,
        end: m.index + m[0].length,
        text: m[0],
      };
    }

    // 时段 + 钟点
    const period = m[1];
    let hour = parseNumber(m[2]);
    if (hour === null || hour > 24) continue;

    // 分钟：固定说法优先，其次中文数字
    let minute = 0;
    if (m[3] === '半') minute = 30;
    else if (m[3] === '一刻') minute = 15;
    else if (m[3] === '三刻') minute = 45;
    else if (m[4] !== undefined) {
      const mm = parseNumber(m[4]);
      // 分钟不合法就放弃这个匹配 —— 宁可漏，不可错
      if (mm === null || mm > 59) continue;
      minute = mm;
    }

    if (period) {
      // 「下午3点」→ 15:00；「晚上8点」→ 20:00
      const rule = PERIOD_TIMES.find(r => r.words.includes(period));
      if (!rule || rule.hour === null) continue;
      // 12 点制换算：下午/晚上/中午 且 小时 < 12 → 加 12
      const isPM = ['中午', '下午', '傍晚', '晚上', '夜里', '夜晚', '半夜'].includes(period);
      if (isPM && hour < 12) hour += 12;
      if (hour > 23) continue;
      return {
        time: `${String(hour).padStart(2, '0')}:${String(minute).padStart(2, '0')}`,
        start: m.index,
        end: m.index + m[0].length,
        text: m[0],
      };
    }

    // 无时段词：纯「3点」是歧义（3点还是15点），不猜
    continue;
  }
  return null;
}

// ==================== 口语前缀清理 ====================

/** 「嗯那个」「那个」「就是」这类开口词，不是内容 */
const FILLER_PREFIX = /^(嗯+|那个|这个|就是|然后|额+|呃+|哎|喂|我说)[，,、\s]*/;

/** 去掉句尾的标点 */
function trimTrailingPunct(s: string): string {
  return s.replace(/[。．.，,、；;！!？?]+$/, '').trim();
}

// ==================== 主函数 ====================

export interface ParseOptions {
  /** 基准日（说话那一刻的今天）。默认取系统当天。 */
  baseDate?: Date;
}

// ==================== 跨日表达 ====================
//
// 「21号到25号出差」「11月21日到23日培训」「下周一到周五带训」
// —— 一件事占好几天，月历上要连成一条线，所以必须解出结束日期。
//
// 认不出来的原则：**宁可漏，不可错**。
// 跨日的结束日期猜错了，界面上会画出一条连错位置的线，
// 比不画更糟。所以每一步都要有明确的依据才认。

/** 一个日期片段解出来的信息 */
interface SpanHalf {
  /** 完整日期 YYYY-MM-DD（只有日号时为 ''） */
  date: string;
  /** 只有日号时的月（1-12），0 = 没月 */
  month: number;
  /** 只有日号时的年 */
  year: number;
  /** 周几（0=周一 … 6=周日），-1 = 不是周型 */
  weekday: number;
  /** 「上周/本周/下周」的周偏移；null = 不带这个前缀 */
  weekOffset: number | null;
}

/**
 * 跨日匹配。
 *
 * 左半与右半各是一个日期片段，顺序很要紧：**长的排前面**，
 * 否则「11月21日」会被「21日」抢走一半。
 */
const SPAN_RE = new RegExp(
  '^(' +
    '[0-9]{1,2}\\s*月\\s*[0-9]{1,2}\\s*[号日]' +          // 11月21日
    '|[0-9]{1,2}\\s*[/]\\s*[0-9]{1,2}' +                   // 11/21
    '|[上下这本]?\\s*周\\s*[一二三四五六日天]' +            // 下周一 / 周五
    '|[0-9零〇一二两三四五六七八九十]{1,3}\\s*[号日]' +     // 21号
  ')\\s*(?:到|至|~|～|—|–)\\s*(' +
    '[0-9]{1,2}\\s*月\\s*[0-9]{1,2}\\s*[号日]' +
    '|[0-9]{1,2}\\s*[/]\\s*[0-9]{1,2}' +
    '|[上下这本]?\\s*周\\s*[一二三四五六日天]' +
    '|[0-9零〇一二两三四五六七八九十]{1,3}\\s*[号日]' +
  ')'
);

/**
 * 解一个日期片段。
 *
 * 返回 month/year 的那一支是给「只给了日号」的情况用的 ——
 * 「11月21日到23日」里，右半只有「23日」，月和年要跟左边借。
 */
function resolveSpanHalf(expr: string, base: Date): SpanHalf | null {
  const s = expr.replace(/\s+/g, '');

  // X月X号
  let m = /^([0-9]{1,2})月([0-9]{1,2})[号日]$/.exec(s);
  if (m) {
    const month = parseInt(m[1], 10);
    const day = parseInt(m[2], 10);
    if (month < 1 || month > 12 || day < 1 || day > 31) return null;
    let d = new Date(base.getFullYear(), month - 1, day);
    if (d.getTime() < base.getTime()) d = new Date(base.getFullYear() + 1, month - 1, day);
    return { date: toDateString(d), month, year: d.getFullYear(), weekday: -1, weekOffset: null };
  }

  // X/X
  m = /^([0-9]{1,2})[/]([0-9]{1,2})$/.exec(s);
  if (m) {
    const month = parseInt(m[1], 10);
    const day = parseInt(m[2], 10);
    if (month < 1 || month > 12 || day < 1 || day > 31) return null;
    let d = new Date(base.getFullYear(), month - 1, day);
    if (d.getTime() < base.getTime()) d = new Date(base.getFullYear() + 1, month - 1, day);
    return { date: toDateString(d), month, year: d.getFullYear(), weekday: -1, weekOffset: null };
  }

  // 上周X / 本周X / 下周X / 周X
  //
  // 注意「周五」和「下周五」不是一回事：
  //   带前缀（上周/本周/下周）→ 日期自己就能定
  //   不带前缀（「周五」）→ 哪个周五要看上下文（「下周一到周五」是下周五）
  m = /^(上|下|这|本)?周([一二三四五六日天])$/.exec(s);
  if (m) {
    const wd = WEEKDAY_CN[m[2]];
    if (wd === undefined) return null;
    const hasPrefix = !!m[1];
    const offset = m[1] === '上' ? -1 : m[1] === '下' ? 1 : 0;
    const d = addDays(startOfWeek(base), offset * 7 + wd);
    return {
      // 没前缀 → 日期留空，等着继承左半的周偏移
      date: hasPrefix ? toDateString(d) : '',
      month: d.getMonth() + 1, year: d.getFullYear(),
      weekday: wd,
      weekOffset: hasPrefix ? offset : null,
    };
  }

  // 只有日号（X号/X日）：月和年留给左边继承
  m = /^([0-9零〇一二两三四五六七八九十]{1,3})[号日]$/.exec(s);
  if (m) {
    const day = parseNumber(m[1]);
    if (day === null || day < 1 || day > 31) return null;
    return { date: '', month: 0, year: 0, weekday: -1, weekOffset: null };
  }

  return null;
}

/**
 * 匹配跨日表达。
 *
 * 返回 null 表示这不是一句跨日的事（或者认不准）—— 那就不跨日。
 */
export function matchSpan(text: string, base: Date): { start: string; end: string; text: string } | null {
  const m = SPAN_RE.exec(text.trim());
  if (!m) return null;

  const left = resolveSpanHalf(m[1], base);
  if (!left) return null;
  const right = resolveSpanHalf(m[2], base);
  if (!right) return null;

  // 左半必须能给出一个确定的日期
  if (!left.date) return null;

  let endDate: string;
  if (right.date) {
    // 右半自带完整日期 → 直接用
    endDate = right.date;
  } else if (right.weekday >= 0) {
    // 右半只给了星期几（「下周一到周五」）→ 继承左半的周偏移
    if (left.weekOffset === null) return null;
    const d = addDays(startOfWeek(base), left.weekOffset * 7 + right.weekday);
    endDate = toDateString(d);
  } else {
    // 右半只给了日号（「11月21日到23日」）→ 月和年跟左半借
    // 右半只给了日号 → 把日号抠出来
    const dayNum = parseNumber((/^([0-9零〇一二两三四五六七八九十]{1,3})/.exec(m[2]) || [])[1] || '');
    if (dayNum === null) return null;
    if (!left.month) {
      // 左半也没有月（「21号到23号」）→ 用基准日的月年
      const d = new Date(base.getFullYear(), base.getMonth(), dayNum);
      if (Number.isNaN(d.getTime())) return null;
      endDate = toDateString(d);
    } else {
      const d = new Date(left.year, left.month - 1, dayNum);
      if (Number.isNaN(d.getTime())) return null;
      // 结束日比开始日早 → 跨月了（11月28日到12月3日）
      endDate = toDateString(d);
    }
  }

  // 结束早于开始 → 认不准，不跨日
  if (endDate < left.date) return null;
  // 跨度上限：超过 60 天多半是用户说错了
  if ((new Date(endDate).getTime() - new Date(left.date).getTime()) / 86400000 > 60) return null;

  return { start: left.date, end: endDate, text: m[0] };
}

/**
 * 解析一句自然语言，返回日期、时间、干净描述。
 *
 * 例：
 *   parseText('上周三 带学员走了 B777 应急演练')
 *   → { date: '2026-10-21', time: '', title: '带学员走了 B777 应急演练', ... }
 */
export function parseText(input: string, options: ParseOptions = {}): ParsedResult {
  const raw = input;
  const base = options.baseDate ?? new Date();

  // 0) 先清口语前缀。「嗯那个今天…」里的「嗯」「那个」都不是内容，
  //    不清掉的话后面的「今天」就不在句首，锚点剥离会失效。
  //    前缀可能叠加（「嗯那个」「那个就是」），要循环清。
  let text = input.trim();
  for (let i = 0; i < 5; i++) {
    const cleaned = text.replace(FILLER_PREFIX, '').trim();
    if (cleaned === text) break;
    text = cleaned;
  }

  if (!text) {
    return {
      date: toDateString(base),
      time: '',
      endDate: '',
      title: '',
      raw,
      dateConfirmed: 0,
      matchedAnchor: null,
    };
  }

  // 1) 先摘时间。时段词跟着钟点一起被摘掉；
  //    单独出现的时段词留在描述里（那是有效信息）。
  let time = '';
  const t = matchTime(text);
  if (t) {
    time = t.time;
    text = text.slice(0, t.start) + ' ' + text.slice(t.end);
  }

  // 1.5) 再看跨日。
  //     「21号到25号出差」这一句里有两个日期，单日锚点只能解出前一个，
  //     后一个会留在描述里变成脏文字。跨日必须整段一起解、整段一起剥。
  let endDate = '';
  let spanText = '';
  const span = matchSpan(text, base);
  if (span) {
    // 跨日段必须也在句首 —— 「上周五的排班从21号改到25号」
    // 里的「21号改到25号」是内容的一部分，不是这件事的日期。
    const beforeSpan = text.slice(0, text.indexOf(span.text)).trim();
    if (beforeSpan === '') {
      endDate = span.end;
      spanText = span.text;
      text = text.slice(text.indexOf(span.text) + span.text.length);
    }
  }

  // 2) 再找日期锚点。只在句首匹配才剥离 —— 句中的日期词是内容的一部分。
  let date = toDateString(base);
  let matchedAnchor: string | null = null;
  let dateConfirmed: 0 | 1 = 0;

  // 跨日已经解出起止日期，就不再走单日锚点（免得把「21号」当成起始日又解一遍）
  if (spanText) {
    date = span!.start;
    matchedAnchor = spanText;
    dateConfirmed = 1;
  } else for (const rule of ANCHOR_RULES) {
    const m = text.match(rule.regex);
    if (!m || m.index === undefined) continue;

    const resolved = rule.resolve(m, base);
    if (!resolved) continue;

    const anchorText = m[0];
    // 锚点必须出现在句首（口语前缀已清理）
    const before = text.slice(0, m.index).trim();
    // 锚点后面紧跟「的」→ 它在修饰一个名词短语，是内容的一部分，
    // 不是「这件事发生在那一天」。
    //   「上周五的排班改了」→ 记录的是今天听到排班变了，「上周五」修饰「排班」
    //   「上周五 带学员走了应急演练」→ 「上周五」指记录日期，整词剥离
    const after = text.slice(m.index + anchorText.length);
    const isModifier = /^\s*的/.test(after);

    if (rule.strip && before === '' && !isModifier) {
      // 句首锚点：算出日期后从描述里剥离
      date = resolved;
      matchedAnchor = anchorText;
      dateConfirmed = 1;
      text = text.slice(m.index + anchorText.length);
      break;
    }

    // 修饰性锚点（后面跟「的」）：不参与日期计算，整词保留在描述里。
    // 「上周五的排班改了」——记录的是「今天听到排班变了」这件事，
    // 「上周五」指明的是哪份排班，不是这件事发生的那一天。
    if (!rule.strip) continue;
    dateConfirmed = 1;
    matchedAnchor = anchorText;
    break;
  }

  // 3) 清理描述：剥离后的多余空白、句尾标点
  let title = text.replace(/\s{2,}/g, ' ').trim();
  title = trimTrailingPunct(title);

  // 4) 判定是否待确认。
  //    判据是「日期解出来了没有」，不是「有没有匹配到锚点」。
  //    「下午3点开会」没写日期，但语义上就是今天下午 —— 落基准日，
  //    用户意图明确，算已确认。
  //    只有当日期与时间都没线索、也无锚点时，才是真正的「解不出」。
  if (matchedAnchor === null && time === '') {
    dateConfirmed = 0;
  } else {
    dateConfirmed = 1;
  }

  return { date, time, endDate, title, raw, dateConfirmed, matchedAnchor };
}

/**
 * 便捷封装：解析并给出「待确认」标记。
 * date_confirmed = 0 时界面应提示用户确认日期。
 */
export function needsDateConfirmation(parsed: ParsedResult): boolean {
  return parsed.dateConfirmed === 0;
}
