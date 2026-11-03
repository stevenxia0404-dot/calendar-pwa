// 菠萝日程 - Cloudflare Workers API v0.4.1
// 邮箱验证码认证 + JWT + D1 数据库

// 家人账号标识。
// v3 时用它决定走哪条 AI 链路（Coze 免费用 / 用户自付），
// v4.0 移除 AI 后这个区分不再影响任何行为，仅作为账号来源标记保留。
// 前端目前不读 role —— 保留是为了不改动登录接口的返回结构。
const FAMILY_EMAILS = ['417118098@qq.com'];

// 墓碑回收的上次执行时刻（模块级，实例内共享）。
// 回收是写操作，而 GET /events 每 30 秒一次，不节流会白吃 D1 写配额。
let lastTombstoneSweep = 0;

// ==================== JWT 工具 ====================

const JWT_SECRET_MIN_LENGTH = 32;

// 进程级随机兜底密钥。
// 仅在 JWT_SECRET 缺失或过短时生成一次，之后整个进程生命周期内保持不变。
// 必须是随机的：固定密钥（哪怕是空字符串）会让任何人都能伪造任意用户的令牌。
let fallbackJwtSecret = null;

function getJwtSecret(env) {
  const secret = env && env.JWT_SECRET;
  if (typeof secret === 'string' && secret.length >= JWT_SECRET_MIN_LENGTH) {
    return secret;
  }
  if (!fallbackJwtSecret) {
    fallbackJwtSecret = `${crypto.randomUUID()}-${crypto.randomUUID()}`;
    console.error('[FATAL] JWT_SECRET 未配置或长度不足 32 位，已启用一次性随机密钥兜底。');
    console.error('[FATAL] 后果：Worker 每次冷启动密钥都会变，届时所有设备都需要重新登录。');
    console.error('[FATAL] 修复：执行 `wrangler secret put JWT_SECRET` 写入至少 32 位随机串。');
  }
  return fallbackJwtSecret;
}

function base64urlEncode(str) {
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function base64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return atob(str);
}

function str2ab(str) {
  const buf = new ArrayBuffer(str.length);
  const view = new Uint8Array(buf);
  for (let i = 0; i < str.length; i++) view[i] = str.charCodeAt(i);
  return buf;
}

async function signJWT(payload, secret) {
  if (!secret) throw new Error('JWT 密钥不可用，无法签发令牌');
  const encoder = new TextEncoder();
  const header = base64urlEncode(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = base64urlEncode(JSON.stringify(payload));
  const data = encoder.encode(`${header}.${body}`);

  const key = await crypto.subtle.importKey(
    'raw', encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, data);
  const sigStr = base64urlEncode(String.fromCharCode(...new Uint8Array(sig)));

  return `${header}.${body}.${sigStr}`;
}

async function verifyJWT(token, secret) {
  if (!secret) return null;
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    // 显式校验算法。
    // 下面用 crypto.subtle.verify('HMAC') 已经限定了算法，
    // alg=none 之类的伪造本来就过不去；这一行是防止将来有人
    // 改成「先读 header.alg 再决定怎么验」，把选择权交给攻击者。
    const header = JSON.parse(new TextDecoder().decode(
      new Uint8Array([...base64urlDecode(parts[0])].map(c => c.charCodeAt(0)))
    ));
    if (header.alg !== 'HS256') return null;

    const encoder = new TextEncoder();
    const data = encoder.encode(`${parts[0]}.${parts[1]}`);
    const sig = new Uint8Array([...base64urlDecode(parts[2])].map(c => c.charCodeAt(0)));

    const key = await crypto.subtle.importKey(
      'raw', encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']
    );
    const valid = await crypto.subtle.verify('HMAC', key, sig, data);
    if (!valid) return null;

    const payload = JSON.parse(new TextDecoder().decode(str2ab(base64urlDecode(parts[1]))));

    // 检查过期
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;

    return payload;
  } catch {
    return null;
  }
}

// ==================== 工具函数 ====================

const ALLOWED_ORIGINS = [
  'https://schedule.boluomate.com',
  'https://schedule-pro.pages.dev',
  'http://localhost:3000',
  'http://localhost:3456',
  'http://localhost:3457',
];

function corsHeaders(origin) {
  const allowed = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  return {
    'Access-Control-Allow-Origin': allowed,
    // Vary 让缓存按 Origin 分开存。没有它，中间缓存可能把一个来源的
    // 响应（带着那个来源的 Allow-Origin）返回给另一个来源。
    'Vary': 'Origin',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
  };
}

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...extraHeaders },
  });
}

// 常量时间字符串比较，用于校验管理密钥。
// 普通 !== 会在第一个不同字符处立即返回，攻击者能靠响应时间差
// 逐位猜出密钥。这里把整串都比一遍，耗时与内容无关。
function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// ==================== 限流 ====================

const RATE_LIMIT_WINDOW = 60 * 1000; // 1 分钟窗口
const RATE_LIMIT_MAX = 60;           // 每个 IP 每分钟最多 60 次

// 限流表清理的上次执行时刻（模块级，实例内共享）。
// 限流表每请求写一行，不清会无限膨胀 —— 表越大 COUNT 越慢，
// 最终反过来拖垮所有请求。每小时清一次过期行就够。
let lastRateLimitSweep = 0;
const RATE_LIMIT_SWEEP_INTERVAL = 3600_000;

async function sweepRateLimits(env, now) {
  if (now - lastRateLimitSweep < RATE_LIMIT_SWEEP_INTERVAL) return;
  lastRateLimitSweep = now;
  try {
    // 只需要保留最近一个窗口内的记录，更早的对计数没有意义
    await env.DB.prepare('DELETE FROM rate_limits WHERE timestamp < ?')
      .bind(now - RATE_LIMIT_WINDOW * 2).run();
  } catch (e) {
    // 清理失败不能挡住正常请求 —— 下个小时再试
    console.error('限流表清理失败:', e && e.message);
  }
}

async function checkRateLimit(env, ip, max = RATE_LIMIT_MAX) {
  const key = `rl:${ip}`;
  const now = Date.now();
  const windowStart = now - RATE_LIMIT_WINDOW;

  await sweepRateLimits(env, now);

  const { results } = await env.DB.prepare(
    'SELECT COUNT(*) as cnt FROM rate_limits WHERE ip = ? AND timestamp > ?'
  ).bind(key, windowStart).all();

  if (results[0]?.cnt >= max) return false;

  await env.DB.prepare(
    'INSERT INTO rate_limits (ip, timestamp) VALUES (?, ?)'
  ).bind(key, now).run();

  return true;
}

// 验证码生成。
// 必须用密码学随机：Math.random() 是可预测的伪随机序列，
// 攻击者若能观察到若干次输出，就能推断后续验证码。
// crypto.getRandomValues 在 Workers 里始终可用。
function generateCode() {
  const buf = new Uint32Array(1);
  crypto.getRandomValues(buf);
  // 取模会引入极轻微的偏斜，但 2^32 % 900000 只差几十，
  // 对 6 位验证码的猜测难度没有实际影响。
  return String(100000 + (buf[0] % 900000));
}

// HTML 转义。所有拼进 HTML 的用户输入都必须过这里。
// & 必须第一个替换，否则会把后续已转义的实体二次转义。
function escapeHtml(value) {
  if (value === null || value === undefined) return '';
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// ==================== 邮箱发送 ====================

async function sendEmail(to, subject, body, env) {
  const sender = env.SENDER_EMAIL || 'noreply@boluomate.com';
  const resp = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${env.RESEND_API_KEY}`,
    },
    body: JSON.stringify({
      from: `菠萝日程 <${sender}>`,
      to: [to],
      subject,
      text: body,
    }),
  });
  const respText = await resp.text();
  if (resp.ok) return { ok: true };
  console.error('Resend error:', resp.status, respText);
  return { ok: false, status: resp.status, error: respText };
}

// ==================== 日程字段校验 ====================
//
// 为什么服务端也要校验：前端有 TypeScript，但 API 是公开的 ——
// 拿到 token 就能直接 curl。不校验的后果是脏数据入库，
// 而脏数据的杀伤力比错误响应大得多：
//   date = "abc"        → 周视图算日期得到 Invalid Date，整屏渲染崩
//   title = 10MB 字符串 → 列表渲染卡死，同步体积暴涨
//   time = "25:99"      → 时间轴定位错乱
// 所以宁可在入口拦住，也不要让它进库。

const EVENT_LIMITS = {
  title: 200,
  location: 100,
  people: 100,
  raw: 1000,
};

const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const TIME_RE = /^([01]\d|2[0-3]):[0-5]\d$/;

// 是否真实存在的日期（挡掉 2026-02-30 这种）
function isValidDateString(s) {
  if (typeof s !== 'string' || !DATE_RE.test(s)) return false;
  const [y, m, d] = s.split('-').map(Number);
  const dt = new Date(Date.UTC(y, m - 1, d));
  return dt.getUTCFullYear() === y && dt.getUTCMonth() === m - 1 && dt.getUTCDate() === d;
}

// 取字符串并截断。长度超限采取「截断」而不是「拒绝」：
// 少几个字总比整条记录写不进去好，且不会让同步队列卡住。
function clampStr(v, max) {
  if (v === null || v === undefined) return '';
  const s = String(v);
  return s.length > max ? s.slice(0, max) : s;
}

/**
 * 校验并规整一条日程的字段。
 * @returns {{ ok: true, value: object } | { ok: false, error: string }}
 */
function normalizeEvent(body) {
  if (!body || typeof body !== 'object') {
    return { ok: false, error: '请求体格式错误' };
  }

  const title = clampStr(body.title, EVENT_LIMITS.title).trim();
  if (!title) return { ok: false, error: '缺少事项内容' };

  const date = typeof body.date === 'string' ? body.date.trim() : '';
  if (!date) return { ok: false, error: '缺少日期' };
  if (!isValidDateString(date)) {
    return { ok: false, error: '日期格式不正确，应为 YYYY-MM-DD' };
  }

  const time = typeof body.time === 'string' ? body.time.trim() : '';
  if (time && !TIME_RE.test(time)) {
    return { ok: false, error: '开始时间格式不正确，应为 HH:MM' };
  }

  const endTime = typeof body.endTime === 'string' ? body.endTime.trim() : '';
  if (endTime && !TIME_RE.test(endTime)) {
    return { ok: false, error: '结束时间格式不正确，应为 HH:MM' };
  }

  // 结束日期（跨日）：空串 = 不跨日；有值必须是合法日期且不早于开始日。
  const endDate = typeof body.endDate === 'string' ? body.endDate.trim() : '';
  if (endDate) {
    if (!isValidDateString(endDate)) {
      return { ok: false, error: '结束日期格式不正确，应为 YYYY-MM-DD' };
    }
    // 结束日早于开始日 —— 那是脏数据，写进去会让月历画不出线
    if (endDate < date) {
      return { ok: false, error: '结束日期不能早于开始日期' };
    }
  }

  // 类型：日程（有时间）/ 任务（没时间）/ 项目。
  // 以前只认 task 和 event，前端存的 'project' 会被悄悄降级成 'event' ——
  // 数据写进去就丢了，界面上「项目」那一栏永远是空的。
  const type = body.type === 'task' ? 'task'
    : body.type === 'project' ? 'project'
    : 'event';

  return {
    ok: true,
    value: {
      title,
      date,
      time,
      endTime,
      endDate,
      location: clampStr(body.location, EVENT_LIMITS.location).trim(),
      people: clampStr(body.people, EVENT_LIMITS.people).trim(),
      raw: clampStr(body.raw, EVENT_LIMITS.raw),
      type,
      completed: body.completed ? 1 : 0,
      dateConfirmed: body.dateConfirmed === 0 ? 0 : 1,
    },
  };
}

// ==================== 认证中间件 ====================

async function requireAuth(request, env) {
  const auth = request.headers.get('Authorization');
  if (!auth?.startsWith('Bearer ')) return null;
  return await verifyJWT(auth.slice(7), getJwtSecret(env));
}

// ==================== 主入口 ====================

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;
    const origin = request.headers.get('Origin') || '*';
    const headers = corsHeaders(origin);

    if (method === 'OPTIONS') {
      return new Response(null, { status: 204, headers });
    }

    // 限流：所有路径都走，包括管理页面和反馈。
    // 管理页原来被跳过，等于给暴力破解开了无限次尝试的口子。
    if (path !== '/') {
      // 管理页走单独的更严格配额，见下方
      const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
      if (!(await checkRateLimit(env, ip))) {
        return json({ error: '请求太频繁，请稍后再试' }, 429, headers);
      }
    }

    // 管理页面：查看反馈
    // 密钥从 env.ADMIN_KEY 读取，不再硬编码在仓库里 ——
    // 硬编码的密码会随代码一起泄露，且改密码要重新部署。
    // 未配置时拒绝服务（fail closed），而不是退回某个默认值。
    if (path === '/' && method === 'GET') {
      const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
      // 管理页单独配额：每分钟 10 次，远低于普通接口，
      // 让暴力破解在实际时间里不可行
      if (!(await checkRateLimit(env, `admin:${ip}`, 10))) {
        return json({ error: '请求太频繁' }, 429, headers);
      }

      const expected = env.ADMIN_KEY;
      if (!expected) {
        return json({
          error: '管理页面未启用：请先执行 `wrangler secret put ADMIN_KEY`',
        }, 503, headers);
      }

      const key = url.searchParams.get('key');
      if (!safeEqual(key || '', expected)) {
        return json({ error: 'Unauthorized' }, 401, headers);
      }

      const { results } = await env.DB.prepare(
        'SELECT id, email, text, created_at FROM feedback ORDER BY created_at DESC LIMIT 100'
      ).all();

      const rows = (results || []).map(r => {
        const t = new Date(r.created_at + 'Z');
        const ts = t.toLocaleString('zh-CN', { month:'2-digit', day:'2-digit', hour:'2-digit', minute:'2-digit' });
        return `<tr class="row">
          <td class="cell email">${escapeHtml(r.email) || '-'}</td>
          <td class="cell text">${escapeHtml(r.text)}</td>
          <td class="cell time">${ts}</td>
        </tr>`;
      }).join('');

      const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>菠萝日程 - 反馈管理</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "PingFang SC", "Microsoft YaHei", sans-serif; background: #F7F5F2; color: #1C1C1C; min-height: 100vh; }
  .header { background: #fff; border-bottom: 1px solid #E8E4DF; padding: 16px 20px; position: sticky; top: 0; z-index: 10; }
  .header-inner { max-width: 900px; margin: 0 auto; display: flex; align-items: center; justify-content: space-between; }
  .brand { display: flex; align-items: center; gap: 10px; }
  .brand img { width: 28px; height: 28px; border-radius: 6px; }
  .brand h1 { font-size: 18px; font-weight: 600; letter-spacing: -0.3px; }
  .brand span { font-size: 13px; color: #A0A0A0; font-weight: 400; }
  .container { max-width: 900px; margin: 0 auto; padding: 20px; }
  .stat { background: #fff; border-radius: 12px; padding: 14px 20px; margin-bottom: 16px; border: 1px solid #E8E4DF; display: flex; align-items: center; gap: 8px; font-size: 14px; color: #5C5C5C; }
  .stat strong { color: #ED6A3B; font-size: 20px; }
  .card { background: #fff; border-radius: 12px; border: 1px solid #E8E4DF; overflow: hidden; }
  table { width: 100%; border-collapse: collapse; }
  th { font-size: 12px; font-weight: 500; color: #A0A0A0; text-align: left; padding: 12px 16px; background: #FAFAF8; border-bottom: 1px solid #E8E4DF; text-transform: uppercase; letter-spacing: 0.5px; }
  .row { border-bottom: 1px solid #F3F1ED; }
  .row:last-child { border-bottom: none; }
  .cell { padding: 12px 16px; font-size: 14px; vertical-align: top; }
  .cell.email { width: 180px; color: #5C5C5C; word-break: break-all; }
  .cell.text { color: #1C1C1C; line-height: 1.5; white-space: pre-wrap; word-break: break-word; }
  .cell.time { width: 100px; color: #A0A0A0; font-size: 13px; white-space: nowrap; }
  .empty { text-align: center; padding: 48px 20px; color: #A0A0A0; font-size: 14px; }
  .footer { text-align: center; padding: 24px; color: #A0A0A0; font-size: 12px; }
  @media (max-width: 640px) {
    .cell.email { width: auto; }
    .cell.time { width: auto; }
    th, .cell { padding: 10px 12px; font-size: 13px; }
  }
</style>
</head>
<body>
<header class="header">
  <div class="header-inner">
    <div class="brand">
      <img src="https://schedule.boluomate.com/icon-192x192.png" alt="">
      <h1>菠萝日程 <span>· 反馈管理</span></h1>
    </div>
    <div style="font-size:13px;color:#A0A0A0;">${new Date().toLocaleDateString('zh-CN')}</div>
  </div>
</header>
<div class="container">
  <div class="stat">
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#ED6A3B" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-4l-4 4z"/></svg>
    共 <strong>${(results || []).length}</strong> 条反馈
  </div>
  <div class="card">
    <table>
      <thead><tr><th>邮箱</th><th>内容</th><th>时间</th></tr></thead>
      <tbody>${rows || '<tr><td colspan="3" class="empty">暂无反馈</td></tr>'}</tbody>
    </table>
  </div>
  <div class="footer">菠萝日程 · 反馈管理后台</div>
</div>
</body>
</html>`;
      return new Response(html, { status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    }

    try {
      // ===== 认证路由 =====

      // 发送验证码
      if (path === '/auth/send-code' && method === 'POST') {
        const { email } = await request.json();
        if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
          return json({ error: '请输入有效的邮箱地址' }, 400, headers);
        }

        // 限流：同一邮箱1分钟内只能发一次
        const recent = await env.DB.prepare(
          "SELECT created_at FROM verification_codes WHERE email = ? AND created_at > datetime('now', '-1 minute')"
        ).bind(email).first();
        if (recent) {
          return json({ error: '发送太频繁，请1分钟后再试' }, 429, headers);
        }

        const code = generateCode();

        const result = await sendEmail(email, '菠萝日程 - 验证码',
          `你的验证码是：${code}\n\n5分钟内有效。\n\n如果你没有在菠萝日程注册，请忽略此邮件。`, env);

        if (!result.ok) {
          let detail = result.error;
          try { detail = JSON.parse(result.error).message || detail; } catch {}
          console.error('验证码邮件发送失败:', detail);
          // 邮件没送达就绝不入库：否则库里会留着一个用户没收到、
          // 却足以登录该账号的有效验证码。
          // 同时绝不回传验证码本身，失败就是失败，不给任何旁路。
          return json({ code_sent: false, error: '验证码邮件发送失败，请稍后重试' }, 200, headers);
        }

        // 邮件已送达才落库，并清掉该邮箱的旧验证码
        await env.DB.prepare('DELETE FROM verification_codes WHERE email = ?').bind(email).run();
        await env.DB.prepare(
          'INSERT INTO verification_codes (email, code) VALUES (?, ?)'
        ).bind(email, code).run();

        return json({ code_sent: true }, 200, headers);
      }

      // 验证码登录
      if (path === '/auth/verify' && method === 'POST') {
        const { email, code } = await request.json();
        if (!email || !code) {
          return json({ error: '请输入邮箱和验证码' }, 400, headers);
        }

        const record = await env.DB.prepare(
          "SELECT * FROM verification_codes WHERE email = ? AND code = ? AND created_at > datetime('now', '-5 minutes')"
        ).bind(email, code).first();

        if (!record) {
          return json({ error: '验证码错误或已过期' }, 401, headers);
        }

        // 删除已使用的验证码
        await env.DB.prepare('DELETE FROM verification_codes WHERE email = ?').bind(email).run();

        // 查找或创建用户
        let user = await env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).first();
        if (!user) {
          await env.DB.prepare('INSERT INTO users (email) VALUES (?)').bind(email).run();
          user = await env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).first();
        }

        const token = await signJWT(
          { userId: user.id, email: user.email, exp: Math.floor(Date.now() / 1000) + 7 * 24 * 3600 },
          getJwtSecret(env)
        );

        const role = FAMILY_EMAILS.includes(email) ? 'family' : 'user';
        return json({ token, user: { id: user.id, email: user.email, role } }, 200, headers);
      }

      // 获取当前用户
      if (path === '/auth/me' && method === 'GET') {
        const payload = await requireAuth(request, env);
        if (!payload) return json({ error: '尚未激活同步，你的数据很安全' }, 401, headers);

        const user = await env.DB.prepare(
          'SELECT id, email, created_at FROM users WHERE id = ?'
        ).bind(payload.userId).first();

        if (!user) return json({ error: '用户不存在' }, 404, headers);
        const role = FAMILY_EMAILS.includes(user.email) ? 'family' : 'user';
        return json({ user: { id: user.id, email: user.email, role } }, 200, headers);
      }

      // 删除账号
      if (path === '/auth/account' && method === 'DELETE') {
        const payload = await requireAuth(request, env);
        if (!payload) return json({ error: '尚未激活同步，你的数据很安全' }, 401, headers);

        await env.DB.prepare('DELETE FROM events WHERE user_id = ?').bind(payload.userId).run();
        await env.DB.prepare('DELETE FROM users WHERE id = ?').bind(payload.userId).run();
        return json({ ok: true }, 200, headers);
      }

      // 反馈提交（无需登录，保护隐私）
      if (path === '/feedback' && method === 'POST') {
        const { text, email } = await request.json();
        if (!text || !text.trim()) return json({ error: '请输入反馈内容' }, 400, headers);
        const uid = (await requireAuth(request, env))?.userId || null;
        await env.DB.prepare('INSERT INTO feedback (user_id, email, text) VALUES (?, ?, ?)')
          .bind(uid, email || '', text.trim().slice(0, 500)).run();
        return json({ ok: true }, 200, headers);
      }

      // 语音转写（服务端 Whisper）—— 语音三层降级的第 1 层
      // 路径与其它端点一致放在根路径（/events、/auth/me、/feedback），
      // 不加 /api 前缀，避免与 Service Worker 的 /api/ 缓存路由纠缠。
      if (path === '/asr' && method === 'POST') {
        const payload = await requireAuth(request, env);
        if (!payload) return json({ error: '请先激活同步' }, 401, headers);

        // 没配 AI binding 就直接告诉前端降级，不要让用户对着一个 500 发呆
        if (!env.AI) {
          return json({
            error: '服务端语音不可用',
            code: 'ASR_UNAVAILABLE',
            fallback: true,
          }, 503, headers);
        }

        // 音频体积上限。Workers AI 单请求体上限约 25MB，
        // 但语音记录不需要那么长 —— 5MB 足够几分钟，挡住超大请求。
        const MAX_AUDIO_BYTES = 5 * 1024 * 1024;
        const contentType = request.headers.get('Content-Type') || '';

        let audioBase64;
        let mime = contentType;
        try {
          if (contentType.includes('application/json')) {
            // 也接受 { audio: base64, mime: 'audio/webm' } 形式
            const body = await request.json();
            audioBase64 = body.audio;
            mime = body.mime || 'application/octet-stream';
          } else {
            const buf = await request.arrayBuffer();
            if (buf.byteLength === 0) {
              return json({ error: '音频为空', code: 'ASR_EMPTY' }, 400, headers);
            }
            if (buf.byteLength > MAX_AUDIO_BYTES) {
              return json({
                error: '音频太长，请分段录制',
                code: 'ASR_TOO_LARGE',
              }, 413, headers);
            }
            const bytes = new Uint8Array(buf);
            let binary = '';
            // 分块拼，避免 apply 参数过多爆栈
            const CHUNK = 0x8000;
            for (let i = 0; i < bytes.length; i += CHUNK) {
              binary += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
            }
            audioBase64 = btoa(binary);
          }
        } catch {
          return json({ error: '音频解析失败', code: 'ASR_BAD_REQUEST' }, 400, headers);
        }

        if (!audioBase64) {
          return json({ error: '缺少音频数据', code: 'ASR_EMPTY' }, 400, headers);
        }

        try {
          const res = await env.AI.run('@cf/openai/whisper-large-v3-turbo', {
            audio: audioBase64,
            language: 'zh',
            task: 'transcribe',
          });

          const text = (res && res.text ? res.text : '').trim();
          return json({ text }, 200, headers);
        } catch (e) {
          // 区分三类失败，对用户的提示与降级策略不同：
          //   额度耗尽 → Cloudflare 抛 429 / code 3036，提示「今日额度已用完」
          //   鉴权/未登录 → 本地开发或账号异常，提示「服务端语音未配置」
          //   其他 → 模型调用本身失败
          const msg = (e && e.message) ? e.message : String(e);
          const status = (e && (e.status || e.code)) ?? '';
          const isQuota = /3036/.test(String(status))
            || /limit exceeded|quota|rate limit|too many requests/i.test(msg);
          const isAuth = /not logged in|unauthorized|authentication|api token/i.test(msg);
          console.error('Whisper 转写失败:', msg);

          const code = isQuota ? 'ASR_QUOTA_EXCEEDED'
            : isAuth ? 'ASR_UNAVAILABLE'
            : 'ASR_FAILED';
          const message = isQuota ? '今日语音额度已用完'
            : isAuth ? '服务端语音未配置'
            : '语音转写失败';

          return json({
            error: message,
            code,
            // 三种都该降级到浏览器语音
            fallback: true,
          }, isQuota ? 429 : isAuth ? 503 : 502, headers);
        }
      }

      // 注：/ai/chat（Coze 代理）已删除。
      // v4.0 移除了全部 AI 链路，前端不再调用它，但它当时仍留在服务端 ——
      // 等于开了一个「任何登录用户都能拿它消耗 Coze 额度」的透传代理，
      // 且 body 完全不受控。死代码不该有对外暴露的面。

      // iCalendar 订阅（无需登录，使用 cal_token 或 test 模式）
      if (path === '/events/ical' && method === 'GET') {
        const calToken = url.searchParams.get('token');

        if (!calToken) return json({ error: 'Missing token' }, 401, headers);

        const row = await env.DB.prepare(
          'SELECT user_id FROM cal_tokens WHERE token = ?'
        ).bind(calToken).first();

        if (!row) return json({ error: 'Invalid token' }, 401, headers);

        // 软删除的记录不推给订阅端 —— 订阅是「看还活着的东西」的通道，
        // 墓碑只用于设备间同步对账。
        const { results: evts } = await env.DB.prepare(
          'SELECT id, title, date, time, end_time, end_date, location, people, raw, type, completed, date_confirmed, updated_at FROM events WHERE user_id = ? AND deleted_at = 0 ORDER BY date, time'
        ).bind(row.user_id).all();

        // iCal 文本转义。
        // 反斜杠必须最先处理，否则后续替换产生的反斜杠会被二次转义。
        // 换行尤其重要：标题里一个换行就能把后面的文本变成新的 iCal 属性，
        // 等于往用户的日历里注入任意字段。
        const icalEscape = (s) => String(s || '')
          .replace(/\\/g, '\\\\')
          .replace(/;/g, '\\;')
          .replace(/,/g, '\\,')
          .replace(/\r\n|\r|\n/g, '\\n');

        const toUTC = (d, t) => {
          const [h, m] = (t || '09:00').split(':');
          return `${d.replace(/-/g, '')}T${h.padStart(2,'0')}${m}00`;
        };
        const addHour = (dt) => {
          const y = parseInt(dt.slice(0,4)), mo = parseInt(dt.slice(4,6))-1, da = parseInt(dt.slice(6,8)),
                hh = parseInt(dt.slice(9,11)), mm = parseInt(dt.slice(11,13));
          const d = new Date(y, mo, da, hh+1, mm);
          return `${d.getFullYear()}${String(d.getMonth()+1).padStart(2,'0')}${String(d.getDate()).padStart(2,'0')}T${String(d.getHours()).padStart(2,'0')}${String(d.getMinutes()).padStart(2,'0')}00`;
        };
        const allDayEnd = (d) => {
          const [y, m, day] = d.split('-').map(Number);
          const next = new Date(y, m - 1, day + 1);
          return `${next.getFullYear()}${String(next.getMonth()+1).padStart(2,'0')}${String(next.getDate()).padStart(2,'0')}`;
        };

        const lines = [
          'BEGIN:VCALENDAR',
          'VERSION:2.0',
          'PRODID:-//菠萝日程//schedule.boluomate.com//',
          'CALSCALE:GREGORIAN',
          'METHOD:PUBLISH',
          'X-WR-CALNAME:菠萝日程',
          'REFRESH-INTERVAL;VALUE=DURATION:PT15M',
        ];

        for (const e of (evts || [])) {
          // 跨日：end_date 存在且晚于 date。
          // 前面几行 SQL 已经把 end_date 查出来了，这里直接用。
          const spansDays = !!e.end_date && e.end_date > e.date;
          if (e.type === 'task') {
            const dateStr = e.date.replace(/-/g, '');
            const prefix = e.completed ? '✓ ' : '';
            lines.push(
              'BEGIN:VEVENT',
              `DTSTART;VALUE=DATE:${dateStr}`,
              // 跨日的任务是一整段多天的全日事件，DTEND 落在结束日的次日
              `DTEND;VALUE=DATE:${allDayEnd(spansDays ? e.end_date : e.date)}`,
              `SUMMARY:${icalEscape(prefix + e.title)}`,
              `DESCRIPTION:${icalEscape(e.raw || '')}`,
              ...(e.location ? [`LOCATION:${icalEscape(e.location)}`] : []),
              `UID:${e.id}`,
              `DTSTAMP:${new Date(e.updated_at).toISOString().replace(/[-:]/g, '').slice(0, 15)}Z`,
              'END:VEVENT'
            );
          } else {
            const dt = toUTC(e.date, e.time);
            // 结束时刻：
            //   当天的事 → 用当天的 end_time，没有就加一小时
            //   跨日的事 → 落在**结束日**；没说几点就取那天的 23:59
            const endDt = spansDays
              ? toUTC(e.end_date, e.end_time || '23:59')
              : (e.end_time ? toUTC(e.date, e.end_time) : addHour(dt));
            lines.push(
              'BEGIN:VEVENT',
              `DTSTART:${dt}`,
              `DTEND:${endDt}`,
              `SUMMARY:${icalEscape(e.title)}`,
              `DESCRIPTION:${icalEscape(e.raw || '')}`,
              ...(e.location ? [`LOCATION:${icalEscape(e.location)}`] : []),
              `UID:${e.id}`,
              `DTSTAMP:${new Date(e.updated_at).toISOString().replace(/[-:]/g, '').slice(0, 15)}Z`,
              'END:VEVENT'
            );
          }
        }

        lines.push('END:VCALENDAR');
        return new Response(lines.join('\r\n'), {
          status: 200,
          headers: {
            'Content-Type': 'text/calendar; charset=utf-8',
            'Content-Disposition': 'inline; filename="schedule.ics"',
            // 必须是 private：这份日历属于某个具体用户，
            // public 会让中间缓存层（CDN、公司代理）有机会把它存下来
            // 再返回给别人。订阅端是客户端自己拉，private 不影响刷新。
            'Cache-Control': 'private, max-age=900',
            ...headers,
          },
        });
      }

      // ===== 日程 API（以下都需要登录） =====

      const payload = await requireAuth(request, env);
      if (!payload) return json({ error: '未登录' }, 401, headers);
      const userId = payload.userId;

      // 获取日程（支持增量同步）
      if (path === '/events' && method === 'GET') {
        const since = url.searchParams.get('since');

        // 服务端时间必须在查询之前取。如果先查后取，查询执行期间写入的
        // 记录（updated_at < server_time）下次增量就拉不到了 —— 会静默漏数据。
        const serverTime = Date.now();

        // 墓碑回收：删除超过 30 天的行清理掉。
        // 墓碑存在的意义是让删除能跨设备传播，30 天足够任何设备追上；
        // 再留着只会让表无限膨胀。
        //
        // 节流：回收是写操作，而 GET 每 30 秒就一次。不节流等于
        // 每天几千次空写，白白吃掉 D1 的写配额。每小时扫一次就够。
        if (serverTime - lastTombstoneSweep > 3600_000) {
          lastTombstoneSweep = serverTime;
          const tombstoneCutoff = serverTime - 30 * 24 * 3600 * 1000;
          await env.DB.prepare(
            'DELETE FROM events WHERE user_id = ? AND deleted_at > 0 AND deleted_at < ?'
          ).bind(userId, tombstoneCutoff).run();
        }

        let query = 'SELECT id, title, date, time, end_time, end_date, location, people, raw, type, completed, date_confirmed, deleted_at, updated_at FROM events WHERE user_id = ?';
        const params = [userId];

        if (since) {
          // 用 >= 而不是 >：同一毫秒内写入的记录不能漏掉。
          // 重复返回无害 —— 写操作是幂等的，覆盖同一条即可。
          query += ' AND updated_at >= ?';
          params.push(parseInt(since, 10) || 0);
        }

        query += ' ORDER BY date, time';

        const { results } = await env.DB.prepare(query).bind(...params).all();
        // server_time 供客户端作为下次的增量起点（客户端时钟不作数）
        return json({ events: results || [], server_time: serverTime }, 200, headers);
      }

      // 创建日程
      if (path === '/events' && method === 'POST') {
        const body = await request.json().catch(() => null);
        const norm = normalizeEvent(body);
        if (!norm.ok) return json({ error: norm.error }, 400, headers);
        const v = norm.value;
        const id = body.id;

        const eventId = typeof id === 'string' && id ? id : crypto.randomUUID();
        // 服务端权威：客户端传的 updatedAt 一律忽略。
        // 设备时钟偏差直接造成丢失更新（两个设备各改一条，谁的时钟快谁赢）。
        const ts = Date.now();

        // 归属校验：客户端可以指定 id，而 events.id 是全局主键，
        // INSERT OR REPLACE 会把别人的同行直接抹掉。写入前必须确认归属。
        if (id) {
          const owner = await env.DB.prepare(
            'SELECT user_id FROM events WHERE id = ?'
          ).bind(eventId).first();
          if (owner && owner.user_id !== userId) {
            return json({ error: '无权修改他人的日程' }, 403, headers);
          }
        }

        // deleted_at = 0：若这个 id 之前被软删除过，重新创建即复活。
        await env.DB.prepare(
          'INSERT INTO events (id, user_id, title, date, time, end_time, end_date, location, people, raw, type, completed, date_confirmed, deleted_at, updated_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, CURRENT_TIMESTAMP) ON CONFLICT(id) DO UPDATE SET title = excluded.title, date = excluded.date, time = excluded.time, end_time = excluded.end_time, end_date = excluded.end_date, location = excluded.location, people = excluded.people, raw = excluded.raw, type = excluded.type, completed = excluded.completed, date_confirmed = excluded.date_confirmed, deleted_at = 0, updated_at = excluded.updated_at'
        ).bind(eventId, userId, v.title, v.date, v.time, v.endTime, v.endDate, v.location, v.people, v.raw, v.type, v.completed, v.dateConfirmed, ts).run();

        return json({ id: eventId, updated_at: ts }, 201, headers);
      }

      // 批量合并同步
      if (path === '/events/merge' && method === 'POST') {
        const { events } = await request.json();
        if (!Array.isArray(events)) {
          return json({ error: '格式错误' }, 400, headers);
        }

        const merged = [];

        // 遗留接口：前端 v4.0 的同步走操作队列（逐条 POST/PUT/DELETE），
        // 不再调用本端点。保留是为了兼容可能还在缓存里的旧版 PWA。
        // 因此这里不再做基于客户端时间戳的冲突判定 ——
        // 客户端时钟不可信，一律以服务端到达顺序为准。
        for (const ev of events) {
          const { id, title, date, time, endTime, endDate, location, people, raw, type, completed } = ev;
          if (!id || !title || !date) continue;

          // 按 id 查归属（不限 user_id）：查不到才可能是自己的新记录，
          // 查到且不属于自己就是别人的 id，必须跳过而不是覆盖。
          const existing = await env.DB.prepare(
            'SELECT user_id, deleted_at FROM events WHERE id = ?'
          ).bind(id).first();

          if (existing && existing.user_id !== userId) {
            console.warn('merge 跳过属于他人的记录:', id);
            continue;
          }

          // 墓碑不复活：别处的删除是明确的用户动作，
          // 一条迟到的批量合并不该把它撤销。
          if (existing && existing.deleted_at) continue;

          const ts = Date.now();
          await env.DB.prepare(
            'INSERT INTO events (id, user_id, title, date, time, end_time, end_date, location, people, raw, type, completed, deleted_at, updated_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, CURRENT_TIMESTAMP) ON CONFLICT(id) DO UPDATE SET title = excluded.title, date = excluded.date, time = excluded.time, end_time = excluded.end_time, end_date = excluded.end_date, location = excluded.location, people = excluded.people, raw = excluded.raw, type = excluded.type, completed = excluded.completed, deleted_at = 0, updated_at = excluded.updated_at'
          ).bind(id, userId, title, date, time || '', endTime || '', endDate || '', location || '', people || '', raw || '', type || 'event', completed ? 1 : 0, ts).run();
          merged.push(id);
        }

        return json({ merged: merged.length }, 200, headers);
      }

      // 切换任务完成状态
      if (path.startsWith('/events/') && path.endsWith('/toggle') && method === 'PUT') {
        const eventId = path.split('/')[2];

        const existing = await env.DB.prepare(
          'SELECT * FROM events WHERE id = ? AND user_id = ?'
        ).bind(eventId, userId).first();

        if (!existing) return json({ error: '日程不存在' }, 404, headers);

        // 客户端可以传明确的 completed（幂等，可安全重放）；
        // 不传则按服务端当前值翻转（兼容旧版 PWA）。
        let body = {};
        try { body = await request.json(); } catch { /* 无 body 时按翻转处理 */ }
        const newCompleted = typeof body.completed === 'boolean'
          ? (body.completed ? 1 : 0)
          : (existing.completed ? 0 : 1);

        const ts = Date.now();
        await env.DB.prepare(
          'UPDATE events SET completed = ?, updated_at = ? WHERE id = ? AND user_id = ?'
        ).bind(newCompleted, ts, eventId, userId).run();

        return json({ completed: !!newCompleted, updated_at: ts }, 200, headers);
      }

      // 更新日程
      if (path.startsWith('/events/') && method === 'PUT') {
        const eventId = path.split('/')[2];
        const body = await request.json().catch(() => null);
        const norm = normalizeEvent(body);
        if (!norm.ok) return json({ error: norm.error }, 400, headers);
        const v = norm.value;

        const existing = await env.DB.prepare(
          'SELECT * FROM events WHERE id = ? AND user_id = ?'
        ).bind(eventId, userId).first();

        if (!existing) return json({ error: '日程不存在' }, 404, headers);

        // 服务端权威：忽略客户端的 updatedAt
        const ts = Date.now();
        // completed 缺省时保留原值 —— 不传就把勾选状态抹成未完成
        // 是一种静默的数据丢失，客户端漏传字段不该有这么大杀伤力。
        const newCompleted = typeof body.completed === 'boolean' ? (body.completed ? 1 : 0) : existing.completed;
        // dateConfirmed 同样缺省保留。
        // 这个字段之前整段漏写，导致「用户改了日期 → 本地待确认标记消失 →
        // 下次全量同步又从服务端拉回 0 → 标记复活」。
        const newDateConfirmed = body.dateConfirmed === 0 ? 0
          : body.dateConfirmed === 1 ? 1
          : existing.date_confirmed;
        // 编辑一条被删掉的记录等于复活它（用户动作比删除新）
        await env.DB.prepare(
          'UPDATE events SET title = ?, date = ?, time = ?, end_time = ?, end_date = ?, location = ?, people = ?, raw = ?, type = ?, completed = ?, date_confirmed = ?, deleted_at = 0, updated_at = ? WHERE id = ? AND user_id = ?'
        ).bind(v.title, v.date, v.time, v.endTime, v.endDate, v.location, v.people, v.raw, v.type, newCompleted, newDateConfirmed, ts, eventId, userId).run();

        return json({ ok: true, updated_at: ts }, 200, headers);
      }

      // 删除日程（软删除）
      if (path.startsWith('/events/') && method === 'DELETE') {
        const eventId = path.split('/')[2];

        const existing = await env.DB.prepare(
          'SELECT * FROM events WHERE id = ? AND user_id = ?'
        ).bind(eventId, userId).first();

        if (!existing) return json({ error: '日程不存在' }, 404, headers);

        // 软删除：墓碑行留在库里，标记删除时刻。
        // 硬删除会让其它设备永远留着本地副本 —— 它们从云端拉不到这条，
        // 也就无从知道该删（v3 的删除不跨设备传播就是这么来的）。
        const ts = Date.now();
        await env.DB.prepare(
          'UPDATE events SET deleted_at = ?, updated_at = ? WHERE id = ? AND user_id = ?'
        ).bind(ts, ts, eventId, userId).run();

        return json({ ok: true, deleted_at: ts, updated_at: ts }, 200, headers);
      }

      // 获取或生成日历订阅 token（复用已有 token，避免旧链接失效）
      if (path === '/auth/cal-token' && method === 'GET') {
        const payload = await requireAuth(request, env);
        if (!payload) return json({ error: '尚未激活同步，你的数据很安全' }, 401, headers);

        const existing = await env.DB.prepare(
          'SELECT token FROM cal_tokens WHERE user_id = ?'
        ).bind(payload.userId).first();

        if (existing) return json({ cal_token: existing.token }, 200, headers);

        const calToken = crypto.randomUUID();
        await env.DB.prepare('INSERT INTO cal_tokens (user_id, token) VALUES (?, ?)')
          .bind(payload.userId, calToken).run();

        return json({ cal_token: calToken }, 200, headers);
      }

      return json({ error: 'Not found' }, 404, headers);

    } catch (error) {
      console.error('API Error:', error);
      return json({ error: '服务器内部错误' }, 500, headers);
    }
  },
};
