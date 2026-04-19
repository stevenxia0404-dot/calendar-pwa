// AI日程管家 - Cloudflare Workers API
// 支持 GitHub OAuth 登录和日程同步

// JWT 工具函数
async function signJWT(payload, secret) {
  const encoder = new TextEncoder();
  const data = encoder.encode(JSON.stringify(payload));
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', key, data);
  const base64Data = btoa(String.fromCharCode(...new Uint8Array(data)));
  const base64Sig = btoa(String.fromCharCode(...new Uint8Array(signature)));
  return `${base64Data}.${base64Sig}`;
}

async function verifyJWT(token, secret) {
  try {
    const [dataB64, sigB64] = token.split('.');
    if (!dataB64 || !sigB64) return null;

    const encoder = new TextEncoder();
    const data = new Uint8Array([...atob(dataB64)].map(c => c.charCodeAt(0)));
    const signature = new Uint8Array([...atob(sigB64)].map(c => c.charCodeAt(0)));

    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );

    const valid = await crypto.subtle.verify('HMAC', key, signature, data);
    if (!valid) return null;

    return JSON.parse(new TextDecoder().decode(data));
  } catch {
    return null;
  }
}

// CORS 响应头
function corsHeaders(origin) {
  return {
    'Access-Control-Allow-Origin': origin || '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Credentials': 'true',
  };
}

// 统一响应格式
function jsonResponse(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...headers,
    },
  });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;
    const origin = request.headers.get('Origin') || env.FRONTEND_URL || '*';

    // 处理 CORS 预检请求
    if (method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: corsHeaders(origin)
      });
    }

    const headers = corsHeaders(origin);
    const jwtSecret = env.JWT_SECRET;

    try {
      // ===== GitHub OAuth 登录 =====

      // 1. 获取 GitHub 登录 URL
      if (path === '/auth/github' && method === 'GET') {
        const clientId = env.GITHUB_CLIENT_ID;
        const redirectUri = `${url.origin}/auth/callback`;
        const githubUrl = `https://github.com/login/oauth/authorize?client_id=${clientId}&redirect_uri=${redirectUri}&scope=user:email`;

        return jsonResponse({ url: githubUrl }, 200, headers);
      }

      // 2. GitHub 回调处理
      if (path === '/auth/callback' && method === 'GET') {
        const code = url.searchParams.get('code');
        if (!code) {
          return jsonResponse({ error: 'No code provided' }, 400, headers);
        }

        // 换取 access_token
        const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
          method: 'POST',
          headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            client_id: env.GITHUB_CLIENT_ID,
            client_secret: env.GITHUB_CLIENT_SECRET,
            code,
          }),
        });

        const tokenData = await tokenRes.json();
        if (!tokenData.access_token) {
          return jsonResponse({ error: 'Failed to get access token' }, 400, headers);
        }

        // 获取用户信息
        const userRes = await fetch('https://api.github.com/user', {
          headers: {
            'Authorization': `Bearer ${tokenData.access_token}`,
            'User-Agent': 'Schedule-Pro',
          },
        });

        const githubUser = await userRes.json();

        // 检查用户是否存在
        let user = await env.DB.prepare(
          'SELECT * FROM users WHERE github_id = ?'
        ).bind(String(githubUser.id)).first();

        // 不存在则创建
        if (!user) {
          await env.DB.prepare(
            'INSERT INTO users (github_id, username, avatar_url) VALUES (?, ?, ?)'
          ).bind(
            String(githubUser.id),
            githubUser.login,
            githubUser.avatar_url
          ).run();

          user = await env.DB.prepare(
            'SELECT * FROM users WHERE github_id = ?'
          ).bind(String(githubUser.id)).first();
        }

        // 生成 JWT
        const token = await signJWT(
          { userId: user.id, username: user.username },
          jwtSecret
        );

        // 重定向回前端，带上 token
        const redirectUrl = `${env.FRONTEND_URL || 'http://localhost:3000'}?token=${token}`;
        return Response.redirect(redirectUrl, 302);
      }

      // 3. 获取当前用户信息
      if (path === '/auth/me' && method === 'GET') {
        const authHeader = request.headers.get('Authorization');
        if (!authHeader?.startsWith('Bearer ')) {
          return jsonResponse({ error: 'Unauthorized' }, 401, headers);
        }

        const token = authHeader.slice(7);
        const payload = await verifyJWT(token, jwtSecret);

        if (!payload) {
          return jsonResponse({ error: 'Invalid token' }, 401, headers);
        }

        const user = await env.DB.prepare(
          'SELECT id, username, avatar_url, created_at FROM users WHERE id = ?'
        ).bind(payload.userId).first();

        if (!user) {
          return jsonResponse({ error: 'User not found' }, 404, headers);
        }

        return jsonResponse({ user }, 200, headers);
      }

      // ===== 日程 API =====

      // 验证登录中间件
      const authHeader = request.headers.get('Authorization');
      if (!authHeader?.startsWith('Bearer ')) {
        return jsonResponse({ error: 'Unauthorized' }, 401, headers);
      }

      const token = authHeader.slice(7);
      const payload = await verifyJWT(token, jwtSecret);

      if (!payload) {
        return jsonResponse({ error: 'Invalid token' }, 401, headers);
      }

      const userId = payload.userId;

      // 1. 获取所有日程
      if (path === '/events' && method === 'GET') {
        const { results } = await env.DB.prepare(
          'SELECT id, title, date, time, raw, created_at FROM events WHERE user_id = ? ORDER BY date, time'
        ).bind(userId).all();

        return jsonResponse({ events: results || [] }, 200, headers);
      }

      // 2. 创建日程
      if (path === '/events' && method === 'POST') {
        const body = await request.json();
        const { title, date, time, raw } = body;

        if (!title || !date || !time) {
          return jsonResponse({ error: 'Missing required fields' }, 400, headers);
        }

        const result = await env.DB.prepare(
          'INSERT INTO events (user_id, title, date, time, raw) VALUES (?, ?, ?, ?, ?)'
        ).bind(userId, title, date, time, raw || '').run();

        return jsonResponse({
          id: result.meta.last_row_id,
          title, date, time, raw
        }, 201, headers);
      }

      // 3. 更新日程
      if (path.startsWith('/events/') && method === 'PUT') {
        const eventId = path.split('/')[2];
        const body = await request.json();
        const { title, date, time } = body;

        // 验证日程属于当前用户
        const existing = await env.DB.prepare(
          'SELECT * FROM events WHERE id = ? AND user_id = ?'
        ).bind(eventId, userId).first();

        if (!existing) {
          return jsonResponse({ error: 'Event not found' }, 404, headers);
        }

        await env.DB.prepare(
          'UPDATE events SET title = ?, date = ?, time = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?'
        ).bind(title, date, time, eventId).run();

        return jsonResponse({ success: true }, 200, headers);
      }

      // 4. 删除日程
      if (path.startsWith('/events/') && method === 'DELETE') {
        const eventId = path.split('/')[2];

        // 验证日程属于当前用户
        const existing = await env.DB.prepare(
          'SELECT * FROM events WHERE id = ? AND user_id = ?'
        ).bind(eventId, userId).first();

        if (!existing) {
          return jsonResponse({ error: 'Event not found' }, 404, headers);
        }

        await env.DB.prepare(
          'DELETE FROM events WHERE id = ?'
        ).bind(eventId).run();

        return jsonResponse({ success: true }, 200, headers);
      }

      // 5. 批量同步（用于初次登录时合并本地数据）
      if (path === '/events/sync' && method === 'POST') {
        const body = await request.json();
        const { events } = body;

        if (!Array.isArray(events)) {
          return jsonResponse({ error: 'Invalid events format' }, 400, headers);
        }

        const insertedIds = [];

        for (const event of events) {
          const { title, date, time, raw } = event;
          if (title && date && time) {
            const result = await env.DB.prepare(
              'INSERT INTO events (user_id, title, date, time, raw) VALUES (?, ?, ?, ?, ?)'
            ).bind(userId, title, date, time, raw || '').run();
            insertedIds.push(result.meta.last_row_id);
          }
        }

        return jsonResponse({
          success: true,
          inserted: insertedIds.length
        }, 200, headers);
      }

      // 404
      return jsonResponse({ error: 'Not found' }, 404, headers);

    } catch (error) {
      console.error('API Error:', error);
      return jsonResponse({ error: 'Internal server error' }, 500, headers);
    }
  },
};
