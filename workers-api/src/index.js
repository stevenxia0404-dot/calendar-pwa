// 菠萝日程 - Cloudflare Workers API v0.4.1
// 邮箱验证码认证 + JWT + D1 数据库

// ==================== JWT 工具 ====================

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

function corsHeaders(origin) {
  return {
    'Access-Control-Allow-Origin': origin || '*',
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

function generateCode() {
  return String(Math.floor(100000 + Math.random() * 900000));
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
  return await verifyJWT(auth.slice(7), env.JWT_SECRET);
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
          <td class="cell email">${r.email || '-'}</td>
          <td class="cell text">${r.text.replace(/</g,'&lt;').replace(/>/g,'&gt;')}</td>
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
        // 删除旧验证码
        await env.DB.prepare('DELETE FROM verification_codes WHERE email = ?').bind(email).run();
        // 存入新验证码
        await env.DB.prepare(
          'INSERT INTO verification_codes (email, code) VALUES (?, ?)'
        ).bind(email, code).run();

        const result = await sendEmail(email, '菠萝日程 - 验证码',
          `你的验证码是：${code}\n\n5分钟内有效。\n\n如果你没有在菠萝日程注册，请忽略此邮件。`, env);

        if (!result.ok) {
          let detail = result.error;
          try { detail = JSON.parse(result.error).message || detail; } catch {}
          return json({ code_sent: false, code_debug: code, error: `邮件发送失败: ${detail}，请手动输入验证码` }, 200, headers);
        }

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
          { userId: user.id, email: user.email, exp: Math.floor(Date.now() / 1000) + 365 * 24 * 3600 },
          env.JWT_SECRET
        );

        return json({ token, user: { id: user.id, email: user.email } }, 200, headers);
      }

      // 获取当前用户
      if (path === '/auth/me' && method === 'GET') {
        const payload = await requireAuth(request, env);
        if (!payload) return json({ error: '尚未激活同步，你的数据很安全' }, 401, headers);

        const user = await env.DB.prepare(
          'SELECT id, email, created_at FROM users WHERE id = ?'
        ).bind(payload.userId).first();

        if (!user) return json({ error: '用户不存在' }, 404, headers);
        return json({ user }, 200, headers);
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

        const { results: evts } = await env.DB.prepare(
          'SELECT id, title, date, time, raw, updated_at FROM events WHERE user_id = ? ORDER BY date, time'
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
          const dt = toUTC(e.date, e.time);
          lines.push(
            'BEGIN:VEVENT',
            `DTSTART:${dt}`,
            `DTEND:${addHour(dt)}`,
            `SUMMARY:${e.title.replace(/[,;\\]/g, '\\$&')}`,
            `DESCRIPTION:${(e.raw || '').replace(/[,;\\]/g, '\\$&')}`,
            `UID:${e.id}`,
            `DTSTAMP:${new Date(e.updated_at).toISOString().replace(/[-:]/g, '').slice(0, 15)}Z`,
            'END:VEVENT'
          );
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
        let query = 'SELECT id, title, date, time, raw, updated_at FROM events WHERE user_id = ?';
        const params = [userId];

        if (since) {
          query += ' AND updated_at > ?';
          params.push(since);
        }

        query += ' ORDER BY date, time';

        const { results } = await env.DB.prepare(query).bind(...params).all();
        return json({ events: results || [] }, 200, headers);
      }

      // 创建日程
      if (path === '/events' && method === 'POST') {
        const { id, title, date, time, raw, updatedAt } = await request.json();
        if (!title || !date || !time) {
          return json({ error: '缺少必填字段' }, 400, headers);
        }

        const now = new Date().toISOString();
        const eventId = id || crypto.randomUUID();
        const ts = updatedAt || Date.now();

        await env.DB.prepare(
          'INSERT OR REPLACE INTO events (id, user_id, title, date, time, raw, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
        ).bind(eventId, userId, title, date, time, raw || '', ts).run();

        return json({ id: eventId, updated_at: ts }, 201, headers);
      }

      // 批量合并同步
      if (path === '/events/merge' && method === 'POST') {
        const { events } = await request.json();
        if (!Array.isArray(events)) {
          return json({ error: '格式错误' }, 400, headers);
        }

        const merged = [];

        for (const ev of events) {
          const { id, title, date, time, raw, updatedAt } = ev;
          if (!id || !title || !date || !time) continue;

          // 检查服务端版本是否更新
          const existing = await env.DB.prepare(
            'SELECT updated_at FROM events WHERE id = ? AND user_id = ?'
          ).bind(id, userId).first();

          if (!existing || (updatedAt && updatedAt > existing.updated_at)) {
            await env.DB.prepare(
              'INSERT OR REPLACE INTO events (id, user_id, title, date, time, raw, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
            ).bind(id, userId, title, date, time, raw || '', updatedAt || Date.now()).run();
            merged.push(id);
          }
        }

        return json({ merged: merged.length }, 200, headers);
      }

      // 更新日程
      if (path.startsWith('/events/') && method === 'PUT') {
        const eventId = path.split('/')[2];
        const { title, date, time, raw, updatedAt } = await request.json();

        const existing = await env.DB.prepare(
          'SELECT * FROM events WHERE id = ? AND user_id = ?'
        ).bind(eventId, userId).first();

        if (!existing) return json({ error: '日程不存在' }, 404, headers);

        const ts = updatedAt || Date.now();
        await env.DB.prepare(
          'UPDATE events SET title = ?, date = ?, time = ?, raw = ?, updated_at = ? WHERE id = ? AND user_id = ?'
        ).bind(title, date, time, raw || '', ts, eventId, userId).run();

        return json({ ok: true, updated_at: ts }, 200, headers);
      }

      // 删除日程
      if (path.startsWith('/events/') && method === 'DELETE') {
        const eventId = path.split('/')[2];

        const existing = await env.DB.prepare(
          'SELECT * FROM events WHERE id = ? AND user_id = ?'
        ).bind(eventId, userId).first();

        if (!existing) return json({ error: '日程不存在' }, 404, headers);

        await env.DB.prepare('DELETE FROM events WHERE id = ? AND user_id = ?')
          .bind(eventId, userId).run();

        return json({ ok: true }, 200, headers);
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
