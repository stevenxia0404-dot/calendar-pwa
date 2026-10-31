// 菠萝日程 - Cloudflare Workers API v0.4.1
// 邮箱验证码认证 + JWT + D1 数据库

// 白名单邮箱 — Coze Bot 模式（开发者付费），其余走直调（用户自付）
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

// ==================== 限流 ====================

const RATE_LIMIT_WINDOW = 60 * 1000; // 1 分钟窗口
const RATE_LIMIT_MAX = 60;           // 每个 IP 每分钟最多 60 次

async function checkRateLimit(env, ip) {
  const key = `rl:${ip}`;
  const now = Date.now();
  const windowStart = now - RATE_LIMIT_WINDOW;

  // 清理过期记录 + 计数
  const { results } = await env.DB.prepare(
    'SELECT COUNT(*) as cnt FROM rate_limits WHERE ip = ? AND timestamp > ?'
  ).bind(key, windowStart).all();

  if (results[0]?.cnt >= RATE_LIMIT_MAX) return false;

  await env.DB.prepare(
    'INSERT INTO rate_limits (ip, timestamp) VALUES (?, ?)'
  ).bind(key, now).run();

  return true;
}

function generateCode() {
  return String(Math.floor(100000 + Math.random() * 900000));
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

    // 限流检查（跳过 OPTIONS 和管理页面）
    if (path !== '/' && path !== '/feedback') {
      const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
      if (!(await checkRateLimit(env, ip))) {
        return json({ error: '请求太频繁，请稍后再试' }, 429, headers);
      }
    }

    // 管理页面：查看反馈
    if (path === '/' && method === 'GET') {
      const key = url.searchParams.get('key');
      if (key !== 'boluomate2026') return json({ error: 'Unauthorized' }, 401, headers);

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

      // Coze AI 代理（需登录）
      if (path === '/ai/chat' && method === 'POST') {
        const payload = await requireAuth(request, env);
        if (!payload) return json({ error: '请先激活同步' }, 401, headers);

        const body = await request.text();
        const res = await fetch('https://api.coze.cn/v3/chat', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${env.COZE_API_TOKEN}`,
          },
          body,
        });

        return new Response(res.body, {
          status: res.status,
          headers: {
            'Content-Type': 'text/event-stream',
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            ...headers,
          },
        });
      }

      // iCalendar 订阅（无需登录，使用 cal_token 或 test 模式）
      if (path === '/events/ical' && method === 'GET') {
        const calToken = url.searchParams.get('token');

        if (calToken === 'test') {
          const testIcal = [
            'BEGIN:VCALENDAR',
            'VERSION:2.0',
            'PRODID:-//菠萝日程//test//',
            'CALSCALE:GREGORIAN',
            'METHOD:PUBLISH',
            'X-WR-CALNAME:菠萝日程测试',
            'BEGIN:VEVENT',
            'DTSTART:20260715T090000Z',
            'DTEND:20260715T100000Z',
            'SUMMARY:测试日程',
            'DESCRIPTION:这是一个测试事件',
            'UID:test-123',
            'END:VEVENT',
            'END:VCALENDAR',
          ].join('\r\n');
          return new Response(testIcal, {
            status: 200,
            headers: { 'Content-Type': 'text/calendar; charset=utf-8', ...headers },
          });
        }

        if (!calToken) return json({ error: 'Missing token' }, 401, headers);

        const row = await env.DB.prepare(
          'SELECT user_id FROM cal_tokens WHERE token = ?'
        ).bind(calToken).first();

        if (!row) return json({ error: 'Invalid token' }, 401, headers);

        // 软删除的记录不推给订阅端 —— 订阅是「看还活着的东西」的通道，
        // 墓碑只用于设备间同步对账。
        const { results: evts } = await env.DB.prepare(
          'SELECT id, title, date, time, end_time, location, people, raw, type, completed, date_confirmed, updated_at FROM events WHERE user_id = ? AND deleted_at = 0 ORDER BY date, time'
        ).bind(row.user_id).all();

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
          if (e.type === 'task') {
            const dateStr = e.date.replace(/-/g, '');
            const prefix = e.completed ? '✓ ' : '';
            lines.push(
              'BEGIN:VEVENT',
              `DTSTART;VALUE=DATE:${dateStr}`,
              `DTEND;VALUE=DATE:${allDayEnd(e.date)}`,
              `SUMMARY:${prefix}${e.title.replace(/[,;\\]/g, '\\$&')}`,
              `DESCRIPTION:${(e.raw || '').replace(/[,;\\]/g, '\\$&')}`,
              ...(e.location ? [`LOCATION:${e.location.replace(/[,;\\]/g, '\\$&')}`] : []),
              `UID:${e.id}`,
              `DTSTAMP:${new Date(e.updated_at).toISOString().replace(/[-:]/g, '').slice(0, 15)}Z`,
              'END:VEVENT'
            );
          } else {
            const dt = toUTC(e.date, e.time);
            const endDt = e.end_time ? toUTC(e.date, e.end_time) : addHour(dt);
            lines.push(
              'BEGIN:VEVENT',
              `DTSTART:${dt}`,
              `DTEND:${endDt}`,
              `SUMMARY:${e.title.replace(/[,;\\]/g, '\\$&')}`,
              `DESCRIPTION:${(e.raw || '').replace(/[,;\\]/g, '\\$&')}`,
              ...(e.location ? [`LOCATION:${e.location.replace(/[,;\\]/g, '\\$&')}`] : []),
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
            'Cache-Control': 'public, max-age=900',
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

        let query = 'SELECT id, title, date, time, end_time, location, people, raw, type, completed, date_confirmed, deleted_at, updated_at FROM events WHERE user_id = ?';
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
        const { id, title, date, time, endTime, location, people, raw, updatedAt, type, completed, dateConfirmed } = await request.json();
        if (!title || !date) {
          return json({ error: '缺少必填字段' }, 400, headers);
        }

        const now = new Date().toISOString();
        const eventId = id || crypto.randomUUID();
        // 服务端权威：客户端传的 updatedAt 一律忽略。
        // 设备时钟偏差直接造成丢失更新（两个设备各改一条，谁的时钟快谁赢）。
        const ts = Date.now();

        // 归属校验：客户端可以指定 id，而 events.id 是全局主键，
        // INSERT OR REPLACE 会把别人的同行直接抹掉。写入前必须确认归属。
        if (id) {
          const owner = await env.DB.prepare(
            'SELECT user_id FROM events WHERE id = ?'
          ).bind(id).first();
          if (owner && owner.user_id !== userId) {
            return json({ error: '无权修改他人的日程' }, 403, headers);
          }
        }

        // deleted_at = 0：若这个 id 之前被软删除过，重新创建即复活。
        await env.DB.prepare(
          'INSERT INTO events (id, user_id, title, date, time, end_time, location, people, raw, type, completed, date_confirmed, deleted_at, updated_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, CURRENT_TIMESTAMP) ON CONFLICT(id) DO UPDATE SET title = excluded.title, date = excluded.date, time = excluded.time, end_time = excluded.end_time, location = excluded.location, people = excluded.people, raw = excluded.raw, type = excluded.type, completed = excluded.completed, date_confirmed = excluded.date_confirmed, deleted_at = 0, updated_at = excluded.updated_at'
        ).bind(eventId, userId, title, date, time || '', endTime || '', location || '', people || '', raw || '', type || 'event', completed ? 1 : 0, dateConfirmed === 0 ? 0 : 1, ts).run();

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
          const { id, title, date, time, endTime, location, people, raw, type, completed } = ev;
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
            'INSERT INTO events (id, user_id, title, date, time, end_time, location, people, raw, type, completed, deleted_at, updated_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, CURRENT_TIMESTAMP) ON CONFLICT(id) DO UPDATE SET title = excluded.title, date = excluded.date, time = excluded.time, end_time = excluded.end_time, location = excluded.location, people = excluded.people, raw = excluded.raw, type = excluded.type, completed = excluded.completed, deleted_at = 0, updated_at = excluded.updated_at'
          ).bind(id, userId, title, date, time || '', endTime || '', location || '', people || '', raw || '', type || 'event', completed ? 1 : 0, ts).run();
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
        const { title, date, time, endTime, location, people, raw, type, completed } = await request.json();

        const existing = await env.DB.prepare(
          'SELECT * FROM events WHERE id = ? AND user_id = ?'
        ).bind(eventId, userId).first();

        if (!existing) return json({ error: '日程不存在' }, 404, headers);

        // 服务端权威：忽略客户端的 updatedAt
        const ts = Date.now();
        // completed 缺省时保留原值 —— 不传就把勾选状态抹成未完成
        // 是一种静默的数据丢失，客户端漏传字段不该有这么大杀伤力。
        const newCompleted = typeof completed === 'boolean' ? (completed ? 1 : 0) : existing.completed;
        // 编辑一条被删掉的记录等于复活它（用户动作比删除新）
        await env.DB.prepare(
          'UPDATE events SET title = ?, date = ?, time = ?, end_time = ?, location = ?, people = ?, raw = ?, type = ?, completed = ?, deleted_at = 0, updated_at = ? WHERE id = ? AND user_id = ?'
        ).bind(title, date, time || '', endTime || '', location || '', people || '', raw || '', type || 'event', newCompleted, ts, eventId, userId).run();

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
