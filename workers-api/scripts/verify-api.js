// 后端接口回归验证
//
// 为什么要有它：后端改动很难靠"看代码"确认对不对。
// 字段校验、墓碑语义、缓存头、注入防护这些，只有真发请求才知道。
// 这个脚本把每一条都变成可重跑的断言。
//
// 用法：
//   1. 起本地 Worker（另开一个终端）：
//        cd workers-api
//        npx wrangler dev --port 8788 --local \
//          --var JWT_SECRET:test_secret_for_local_verify_at_least_32chars
//   2. 插一个测试用户（只做一次，events.user_id 有外键约束）：
//        npx wrangler d1 execute schedule_pro_db --local \
//          --command "INSERT OR IGNORE INTO users (id,email) VALUES (1,'verify@example.com')"
//   3. 跑验证：
//        node scripts/verify-api.js
//
// 环境变量可覆盖：PORT / SECRET
// 注意：只对本地 --local 的 Worker 有意义，不要指向生产。
const crypto = require('crypto');
const http = require('http');

const HOST = '127.0.0.1';
const PORT = Number(process.env.PORT || 8788);
const SECRET = process.env.SECRET || 'test_secret_for_local_verify_at_least_32chars';

const results = [];
function check(name, ok, detail) {
  results.push({ name, ok, detail });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? '  → ' + detail : ''}`);
}

function b64url(input) {
  return Buffer.from(input).toString('base64url');
}

function signJWT(payload) {
  const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = b64url(JSON.stringify(payload));
  const data = `${header}.${body}`;
  const sig = crypto.createHmac('sha256', SECRET).update(data).digest('base64url');
  return `${data}.${sig}`;
}

function req(method, path, { body, token, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? null : (typeof body === 'string' ? body : JSON.stringify(body));
    const h = { ...headers };
    if (payload) { h['Content-Type'] = 'application/json'; h['Content-Length'] = Buffer.byteLength(payload); }
    if (token) h['Authorization'] = `Bearer ${token}`;

    const r = http.request({ host: HOST, port: PORT, path, method, headers: h }, res => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(d); } catch {}
        resolve({ status: res.statusCode, body: d, json, headers: res.headers });
      });
    });
    r.on('error', reject);
    if (payload) r.write(payload);
    r.end();
  });
}

(async () => {
  const exp = Math.floor(Date.now() / 1000) + 3600;
  const token = signJWT({ userId: 1, email: 'verify@example.com', exp });
  const today = new Date().toISOString().slice(0, 10);

  console.log('=== 1. 鉴权基线 ===');
  const noAuth = await req('GET', '/events');
  check('无 token 访问被拒', noAuth.status === 401, `status=${noAuth.status}`);

  const withAuth = await req('GET', '/events', { token });
  check('有效 token 可读', withAuth.status === 200, `status=${withAuth.status}`);

  console.log('\n=== 2. 创建（正常路径，不能破坏原有功能）===');
  const evId = 'verify-' + Date.now();
  const create = await req('POST', '/events', {
    token,
    body: { id: evId, title: '验证用日程', date: today, time: '09:00', endTime: '10:00', location: '测试地点', people: '张教员', raw: '验证用日程', type: 'event', completed: false, dateConfirmed: 1 },
  });
  check('正常数据可创建', create.status === 201, `status=${create.status} ${create.body.slice(0, 80)}`);
  check('返回服务端时间戳', typeof create.json?.updated_at === 'number', String(create.json?.updated_at));

  console.log('\n=== 3. 字段校验（新增防护）===');
  const badDate = await req('POST', '/events', { token, body: { id: 'bad-1', title: 'x', date: 'abc' } });
  check('拒绝非法日期格式', badDate.status === 400, `status=${badDate.status} ${badDate.json?.error || ''}`);

  const fakeDate = await req('POST', '/events', { token, body: { id: 'bad-2', title: 'x', date: '2026-02-30' } });
  check('拒绝不存在的日期(2月30日)', fakeDate.status === 400, `status=${fakeDate.status} ${fakeDate.json?.error || ''}`);

  const emptyTitle = await req('POST', '/events', { token, body: { id: 'bad-3', title: '   ', date: today } });
  check('拒绝空标题', emptyTitle.status === 400, `status=${emptyTitle.status} ${emptyTitle.json?.error || ''}`);

  const badTime = await req('POST', '/events', { token, body: { id: 'bad-4', title: 'x', date: today, time: '25:99' } });
  check('拒绝非法时间', badTime.status === 400, `status=${badTime.status} ${badTime.json?.error || ''}`);

  const longTitle = await req('POST', '/events', {
    token,
    body: { id: 'long-1', title: 'A'.repeat(500), date: today },
  });
  check('超长标题被接受并截断（不丢数据）', longTitle.status === 201, `status=${longTitle.status}`);

  // 读回来确认截断到 200
  const listAfterLong = await req('GET', '/events', { token });
  const longRow = (listAfterLong.json?.events || []).find(e => e.id === 'long-1');
  check('超长标题实际存为 200 字符', longRow && longRow.title.length === 200, `len=${longRow?.title?.length}`);

  console.log('\n=== 4. 关键修复：PUT 更新 date_confirmed ===');
  // 先建一条 date_confirmed=0（规则没解出日期）
  const pendingId = 'pending-' + Date.now();
  await req('POST', '/events', {
    token,
    body: { id: pendingId, title: '待确认的日程', date: today, dateConfirmed: 0 },
  });
  const beforePut = (await req('GET', '/events', { token })).json?.events?.find(e => e.id === pendingId);
  check('初始 date_confirmed=0 写入成功', beforePut?.date_confirmed === 0, `= ${beforePut?.date_confirmed}`);

  // 用户改日期并确认 → PUT 带 dateConfirmed: 1
  const putRes = await req('PUT', `/events/${pendingId}`, {
    token,
    body: { title: '已确认的日程', date: today, time: '', endTime: '', location: '', people: '', raw: '', type: 'task', completed: false, dateConfirmed: 1 },
  });
  check('PUT 成功', putRes.status === 200, `status=${putRes.status}`);

  const afterPut = (await req('GET', '/events', { token })).json?.events?.find(e => e.id === pendingId);
  check('★ date_confirmed 已更新为 1（本次修复的核心）', afterPut?.date_confirmed === 1, `= ${afterPut?.date_confirmed}`);
  check('标题同步更新', afterPut?.title === '已确认的日程', afterPut?.title);

  // 再验一次：不传 dateConfirmed 时应保留原值，不能抹成 0
  const putNoField = await req('PUT', `/events/${pendingId}`, {
    token,
    body: { title: '再改一次', date: today, type: 'task', completed: false },
  });
  const afterPut2 = (await req('GET', '/events', { token })).json?.events?.find(e => e.id === pendingId);
  check('PUT 不传 dateConfirmed 时保留原值', afterPut2?.date_confirmed === 1, `= ${afterPut2?.date_confirmed}`);

  console.log('\n=== 5. 删除与墓碑 ===');
  const del = await req('DELETE', `/events/${evId}`, { token });
  check('删除成功', del.status === 200, `status=${del.status}`);

  // 墓碑（deleted_at > 0）必须返回给客户端 —— 这是删除能跨设备传播的前提：
  // 客户端靠「收到带 deleted_at 的记录」才知道该删本地那条。
  // 全量接口还有另一重用途：服务端没有的本地记录也要跟着删（删除对账）。
  const fullList = (await req('GET', '/events', { token })).json?.events || [];
  const tomb = fullList.find(e => e.id === evId);
  check('墓碑随全量返回（供客户端对账）', !!tomb && tomb.deleted_at > 0, tomb ? `deleted_at=${tomb.deleted_at}` : '未返回');

  // 增量也要带墓碑，否则离线一段时间后回来收不到删除信号
  const incList = (await req('GET', '/events?since=1', { token })).json?.events || [];
  const incTomb = incList.find(e => e.id === evId);
  check('墓碑随增量返回', !!incTomb && incTomb.deleted_at > 0, incTomb ? `deleted_at=${incTomb.deleted_at}` : '未返回');

  // iCal 订阅端不该看到已删除的
  const calForDel = await req('GET', '/auth/cal-token', { token });
  if (calForDel.json?.cal_token) {
    const icsDel = await req('GET', `/events/ical?token=${calForDel.json.cal_token}`);
    check('iCal 不输出已删除的记录', !icsDel.body.includes(evId), icsDel.body.includes(evId) ? '仍输出' : '已排除');
  }

  console.log('\n=== 6. 已删除的死代码与后门 ===');
  const aiChat = await req('POST', '/ai/chat', { token, body: { query: 'hi' } });
  check('/ai/chat 已下线', aiChat.status === 404, `status=${aiChat.status}`);

  const icalTest = await req('GET', '/events/ical?token=test');
  check('ical ?token=test 后门已移除', icalTest.status === 401, `status=${icalTest.status}`);

  console.log('\n=== 7. 管理页 ===');
  const adminNoKey = await req('GET', '/');
  check('无 key 访问管理页被拒', adminNoKey.status === 401 || adminNoKey.status === 503, `status=${adminNoKey.status}`);
  const adminWrong = await req('GET', '/?key=boluomate2026');
  check('旧硬编码密码已失效', adminWrong.status === 401 || adminWrong.status === 503, `status=${adminWrong.status}`);

  console.log('\n=== 8. iCal 缓存策略 ===');
  const calTok = await req('GET', '/auth/cal-token', { token });
  check('可获取日历 token', calTok.status === 200, `status=${calTok.status}`);
  if (calTok.json?.cal_token) {
    const ics = await req('GET', `/events/ical?token=${calTok.json.cal_token}`);
    const cc = String(ics.headers['cache-control'] || '');
    check('iCal 缓存为 private', cc.includes('private'), cc || '(无)');
    check('iCal 可正常返回', ics.status === 200, `status=${ics.status}, ${ics.body.split('\r\n').length} 行`);
  }

  console.log('\n=== 9. iCal 注入防护 ===');
  const injectId = 'inject-' + Date.now();
  await req('POST', '/events', {
    token,
    body: { id: injectId, title: '正常标题\r\nSUMMARY:被注入的内容', date: today, time: '08:00', type: 'event' },
  });
  if (calTok.json?.cal_token) {
    const ics2 = await req('GET', `/events/ical?token=${calTok.json.cal_token}`);
    const hasInjectedLine = ics2.body.split('\r\n').some(l => l.startsWith('SUMMARY:被注入的内容'));
    check('标题中的换行无法注入新 iCal 行', hasInjectedLine === false, hasInjectedLine ? '注入成功（危险）' : '已转义');
  }

  console.log('\n=== 结果汇总 ===');
  const pass = results.filter(r => r.ok).length;
  console.log(`${pass}/${results.length} 通过`);
  for (const r of results.filter(x => !x.ok)) console.log(`  FAIL: ${r.name} → ${r.detail || ''}`);

  process.exit(results.every(r => r.ok) ? 0 : 1);
})().catch(e => { console.log('FATAL ' + e.message + '\n' + e.stack); process.exit(1); });
