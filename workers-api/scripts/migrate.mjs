#!/usr/bin/env node
// 迁移执行器 —— 让 D1 迁移可重复执行
//
// 为什么需要它：
//   D1 的 SQLite 不支持 `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`
//   （实测 SQLITE_ERROR: near "EXISTS"）。裸跑 wrangler d1 execute --file
//   第二次就会在 ALTER TABLE 处报错。001 是 DROP TABLE 重建，绝不能重跑。
//
// 做法：
//   1. 先建 schema_migrations 表
//   2. 逐个迁移文件：
//      - 版本已在 schema_migrations → 跳过
//      - 否则执行文件内容
//      - 执行前探测该文件会加的列是否已存在，存在则跳过对应的 ALTER
//      - 成功后登记版本
//
// 用法：
//   node scripts/migrate.mjs              # 本地（--local）
//   node scripts/migrate.mjs --remote     # 线上 D1
//   node scripts/migrate.mjs --list       # 只看状态，不执行
//
// 幂等性保证：
//   - 同一个迁移重复执行 → 版本表拦下
//   - 列已存在但版本未登记（如手工改过库）→ pragma_table_info 探测拦下

import { readFileSync, readdirSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';

const __dirname = dirname(fileURLToPath(import.meta.url));
const WORKERS_DIR = join(__dirname, '..');
const MIGRATIONS_DIR = join(WORKERS_DIR, 'migrations');
const TMP_DIR = join(WORKERS_DIR, '.wrangler', 'migrate-tmp');
const DB_NAME = 'schedule_pro_db';

// 用项目本地的 wrangler（3.114.17），不用 npx —— npx 会拉到最新版 4.x，
// 参数行为与部署时不一致，迁移结果不能复现。
const WRANGLER_BIN = join(WORKERS_DIR, 'node_modules', '.bin',
  process.platform === 'win32' ? 'wrangler.cmd' : 'wrangler');

const REMOTE = process.argv.includes('--remote');
const LIST_ONLY = process.argv.includes('--list');
const TARGET = REMOTE ? '--remote' : '--local';

// 本地状态目录：可用 --persist-to=DIR 指定，默认走仓库的 .wrangler/state
const persistArg = process.argv.find(a => a.startsWith('--persist-to='));
const PERSIST = persistArg ? persistArg.split('=')[1] : null;

// Windows 上 .cmd 必须走 shell；但 shell 会重新按空格/换行拆分参数，
// 所以这里把整条命令拼成一个字符串，SQL 压成单行并用双引号保护。
// 绝不能把多行 SQL 直接塞进 --command，cmd 处理不了换行。
function wrangler(args, { silent = false } = {}) {
  const quote = s => `"${String(s).replace(/"/g, '\\"').replace(/\r?\n/g, ' ')}"`;
  const parts = [quote(WRANGLER_BIN), 'd1', 'execute', quote(DB_NAME), ...args.map(quote)];
  if (!REMOTE && PERSIST) parts.push(`--persist-to=${quote(PERSIST)}`);
  parts.push('--json');

  const out = execFileSync(parts.join(' '), {
    cwd: WORKERS_DIR,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    shell: true,
  });
  if (!silent) process.stdout.write(out);
  return out;
}

// 从 wrangler 的 JSON 输出里取出 results 数组
function parseResults(stdout) {
  const start = stdout.indexOf('[');
  const end = stdout.lastIndexOf(']');
  if (start < 0 || end < 0) return [];
  try {
    const parsed = JSON.parse(stdout.slice(start, end + 1));
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function query(sql) {
  const out = wrangler([TARGET, `--command=${sql}`], { silent: true });
  const blocks = parseResults(out);
  const results = [];
  for (const b of blocks) if (b.success && Array.isArray(b.results)) results.push(...b.results);
  return results;
}

function tableExists(name) {
  const r = query(
    `SELECT name FROM sqlite_master WHERE type='table' AND name='${name}'`
  );
  return r.length > 0;
}

function columnExists(table, column) {
  const r = query(
    `SELECT name FROM pragma_table_info('${table}') WHERE name='${column}'`
  );
  return r.length > 0;
}

function appliedVersions() {
  if (!tableExists('schema_migrations')) return new Set();
  const r = query('SELECT version FROM schema_migrations');
  return new Set(r.map(x => x.version));
}

// 从迁移文件里抽出「会加哪些列」，用于执行前的存在性探测
function parseAddedColumns(sql) {
  const cols = [];
  const re = /ALTER\s+TABLE\s+(\w+)\s+ADD\s+COLUMN\s+(\w+)/gi;
  let m;
  while ((m = re.exec(sql)) !== null) cols.push({ table: m[1], column: m[2] });
  return cols;
}

// 从迁移文件里抽出「会建哪些表」
function parseCreatedTables(sql) {
  const tables = [];
  const re = /CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)/gi;
  let m;
  while ((m = re.exec(sql)) !== null) tables.push(m[1]);
  return tables;
}

// 判断某个迁移的目标结构是否真的到位。
//
// 「已登记」不等于「跑过了」—— 历史回填会把没跑过的迁移标成已应用，
// 于是迁移器永远跳过它，缺失的列永远补不上（生产环境真踩过：
// 006/007 已登记，但 location/people/end_time 三个列从没加上，
// 结果所有写入报「no column named end_time」，同步全断）。
//
// 所以每次跑迁移都要核对一遍结构，对不上就补跑。
function migrationSatisfied(file) {
  const sql = readFileSync(join(MIGRATIONS_DIR, file), 'utf8');
  const cols = parseAddedColumns(sql);
  if (cols.length) {
    return cols.every(c => columnExists(c.table, c.column));
  }
  const tables = parseCreatedTables(sql);
  if (tables.length) {
    return tables.every(t => tableExists(t));
  }
  return true; // 判不出目标就别添乱
}

// 把文件里的 ALTER TABLE ADD COLUMN 语句替换成「列已存在则跳过」的等价形式
// D1 的 execute --file 不支持条件执行，所以这里做文本级重写：
//   把 `ALTER TABLE t ADD COLUMN c ...;` 改为 `ALTER TABLE t ADD COLUMN c ...;`
// 并在执行前自行判断跳过 —— 也就是说，只把「需要跳过的语句」剔除。
function stripExistingColumns(sql) {
  const lines = sql.split('\n');
  const kept = [];
  for (const line of lines) {
    const m = /^\s*ALTER\s+TABLE\s+(\w+)\s+ADD\s+COLUMN\s+(\w+)/i.exec(line);
    if (m && columnExists(m[1], m[2])) {
      kept.push(`-- [skip] 列 ${m[1]}.${m[2]} 已存在，跳过：${line.trim()}`);
      continue;
    }
    kept.push(line);
  }
  return kept.join('\n');
}

function listMigrations() {
  return readdirSync(MIGRATIONS_DIR)
    .filter(f => f.endsWith('.sql'))
    .sort();
}

// ---------- 主流程 ----------

const files = listMigrations();
const versions = appliedVersions();

console.log(`迁移目录：${MIGRATIONS_DIR}`);
console.log(`目标：${REMOTE ? '线上 D1' : '本地 D1'}`);
console.log(`已登记版本：${versions.size ? [...versions].join(', ') : '（无）'}`);
console.log('');

if (LIST_ONLY) {
  for (const f of files) {
    const v = f.replace(/\.sql$/, '');
    console.log(`  ${versions.has(v) ? '✓ 已应用' : '○ 待执行'}  ${f}`);
  }
  process.exit(0);
}

// 1) 版本表与历史登记
//    旧库要回填历史版本登记，但「旧库」不等于「所有历史迁移都跑过」。
//
//    踩过的坑（生产环境）：旧库只有一张 events 表（v3 时代建的），
//    这里一刀切把 001~007 全标成「已应用」—— 其中 006/007 是
//    ADD COLUMN location/people/end_time，从没真正执行过。
//    结果：版本表说「跑过了」，列却不存在，
//    之后所有写入都报 `table events has no column named end_time`，
//    同步全断，而且版本表让迁移器永远不会再补这个列。
//
//    所以回填必须逐个验证「这个迁移的目标结构是否真的到位」，
//    到位才登记；没到位就让它正常执行（执行器本身会剔除已存在的列，
//    重复执行是安全的）。
const HISTORY_CHECKS = [
  ['001_v0.4.0', () => tableExists('events')],
  ['002_cal_tokens', () => tableExists('cal_tokens')],
  ['003_feedback', () => tableExists('feedback')],
  ['004_tasks', () => columnExists('events', 'type')],
  ['005_rate_limits', () => tableExists('rate_limits')],
  ['006_location_people', () => columnExists('events', 'location') && columnExists('events', 'people')],
  ['007_end_time', () => columnExists('events', 'end_time')],
];

if (!tableExists('schema_migrations')) {
  console.log('→ 创建 schema_migrations 表');
  wrangler([TARGET, `--command=CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at DATETIME DEFAULT CURRENT_TIMESTAMP)`]);
}
if (tableExists('events')) {
  const known = appliedVersions();
  if (!known.has('001_v0.4.0')) {
    // 逐个检查：目标结构到位的才回填登记，没到位的留给正常执行
    const done = [];
    const pending = [];
    for (const [version, check] of HISTORY_CHECKS) {
      if (known.has(version)) continue;
      (check() ? done : pending).push(version);
    }
    if (done.length) {
      const vals = done.map(v => `'${v}'`).join(',');
      console.log(`→ 回填历史版本登记（结构已到位）：${done.join(', ')}`);
      wrangler([TARGET, `--command=INSERT OR IGNORE INTO schema_migrations (version) VALUES (${vals})`]);
    }
    if (pending.length) {
      console.log(`→ 以下历史迁移结构未到位，将正常执行补齐：${pending.join(', ')}`);
    }
  }
}

// 2) 逐个执行
mkdirSync(TMP_DIR, { recursive: true });
let applied = 0, skipped = 0;
for (const f of files) {
  const v = f.replace(/\.sql$/, '');

  // 实时查版本表：前一个迁移刚登记的版本要立刻生效
  if (appliedVersions().has(v)) {
    // 已登记 ≠ 结构到位。历史回填可能把没真跑过的迁移标成「已应用」，
    // 那时候缺列会永远补不上。核对一下，对不上就补跑。
    if (migrationSatisfied(f)) {
      console.log(`  ○ 跳过 ${f}（已登记，结构已到位）`);
      skipped++;
      continue;
    }
    console.log(`  ⚠ ${f} 版本已登记但结构未到位 —— 补跑（生产踩过：登记了但列没加上）`);
  }

  // 001 是破坏性重建（DROP TABLE + CREATE），
  // 但它同时也是建表的那一步：新库上必须执行，旧库上必须跳过。
  // 判断依据是「events 表在不在」，不是「版本登记没有」。
  if (v === '001_v0.4.0') {
    if (tableExists('events')) {
      console.log(`  ○ 跳过 ${f}（events 表已存在，001 会 DROP 重建，绝不重跑）`);
      skipped++;
      continue;
    }
    console.log(`  → 执行 ${f}（建表，新库）`);
    try {
      wrangler([TARGET, `--file=${join(MIGRATIONS_DIR, f)}`]);
    } catch (e) {
      console.error(`  ✗ ${f} 执行失败：${(e.stderr || e.message || '').toString().split('\n').slice(0, 4).join('\n')}`);
      process.exit(1);
    }
    wrangler([TARGET, `--command=INSERT OR IGNORE INTO schema_migrations (version) VALUES ('${v}')`]);
    applied++;
    continue;
  }

  const raw = readFileSync(join(MIGRATIONS_DIR, f), 'utf8');
  const addedCols = parseAddedColumns(raw);

  // 逐列判断：已存在的列要从 SQL 里剔除，
  // 否则 D1 会在 ALTER TABLE ADD COLUMN 处报「duplicate column name」。
  const existing = addedCols.filter(c => columnExists(c.table, c.column));
  if (existing.length) {
    console.log(`  → ${f}：列已存在 ${existing.map(c => `${c.table}.${c.column}`).join(', ')}，执行时剔除`);
  }
  const sql = stripExistingColumns(raw);

  // 所有要加的列都已存在 → 直接登记版本，不执行
  if (addedCols.length && addedCols.every(c => columnExists(c.table, c.column))) {
    console.log(`  → ${f}：目标列均已存在，仅登记版本`);
    wrangler([TARGET, `--command=INSERT OR IGNORE INTO schema_migrations (version) VALUES ('${v}')`]);
    applied++;
    continue;
  }

  // 用剔除后的内容执行（而不是原文件）—— 原文件里仍有会报错的 ALTER
  const tmpFile = join(TMP_DIR, `${v}.sql`);
  writeFileSync(tmpFile, sql, 'utf8');

  console.log(`  → 执行 ${f}`);
  try {
    wrangler([TARGET, `--file=${tmpFile}`]);
  } catch (e) {
    console.error(`  ✗ ${f} 执行失败：${(e.stderr || e.message || '').toString().split('\n').slice(0, 4).join('\n')}`);
    process.exit(1);
  }
  wrangler([TARGET, `--command=INSERT OR IGNORE INTO schema_migrations (version) VALUES ('${v}')`]);
  applied++;
}

console.log('');
console.log(`完成：新执行 ${applied} 个，跳过 ${skipped} 个`);
rmSync(TMP_DIR, { recursive: true, force: true });

// 3) 结果自检
const finalVersions = appliedVersions();
console.log(`schema_migrations 现有 ${finalVersions.size} 条：${[...finalVersions].join(', ')}`);
if (tableExists('events')) {
  const cols = query("SELECT name FROM pragma_table_info('events')");
  const names = cols.map(c => c.name);
  console.log(`events 表字段：${names.join(', ')}`);
  for (const c of ['date_confirmed', 'deleted_at']) {
    console.log(`  ${names.includes(c) ? '✓' : '✗'} ${c}`);
  }
  const idx = query("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='events'");
  console.log(`events 索引：${idx.map(i => i.name).join(', ')}`);
}
