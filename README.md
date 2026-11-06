# 菠萝日程

一个说话就记、记完自动排进日历的私人工作本。

- **前端** `schedule.boluomate.com` —— Next.js 静态导出，部署在 Cloudflare Pages
- **后端** `schedule-api.boluomate.com` —— Cloudflare Workers + D1

一句话记一条，不用填表；课表从 Excel 导进来；写周报时按时间段导出。

---

## 它解决什么

两件事：

1. **课表统一视图** —— 课表散在别的地方看，要汇总成一个「我什么时候在哪、和谁」。
2. **随手记 + 周报溯源** —— 走路时想到什么说一句，周五写周报时能翻出「这周哪天我干了啥」。

设计文档在 `docs/菠萝日程-v4.0-产品说明.md`，那是改这个项目之前先读的一份。

---

## 快速开始

```bash
# 前端
npm install
npm run dev            # http://localhost:3000

# 后端（另开一个终端）
cd workers-api
npm install
npm run migrate        # 建本地 D1 库并跑全部迁移
npm run dev            # http://localhost:8787
```

前端默认连生产接口 `https://schedule-api.boluomate.com`。连本地后端：

```bash
NEXT_PUBLIC_API_URL=http://localhost:8787 npm run dev
```

> 本地 `wrangler dev` 会连上真实的 Cloudflare 边缘节点（Workers AI 等），
> 需要先 `wrangler login`。

---

## 常用命令

| 命令 | 作用 |
|---|---|
| `npm run dev` | 起前端开发服务器 |
| `npm run build` | 生产构建，产物在 `dist/` |
| `npm test` | 跑全部单元测试（Node 内置 test runner，零新依赖） |
| `npm run test:cross` | 日期解析的独立交叉验证（另写一份参考实现重算比对） |
| `npm run typecheck` | TypeScript 类型检查 |
| `npm run lint` | ESLint |
| `cd workers-api && npm run migrate` | 执行数据库迁移（本地） |
| `cd workers-api && npm run migrate:remote` | 执行数据库迁移（线上） |
| `cd workers-api && npm run verify:api` | 后端接口回归验证（27 项断言，需先起本地 Worker） |

**测试怎么跑**：Node 22 自带 `--experimental-strip-types`，所以 `.ts` 测试文件能直接跑，
不需要装 ts-node / vitest。`tests/` 下按模块分文件。

---

## 架构

```
浏览器（PWA）
 ├─ localStorage        日程 + 令牌 + 操作队列
 ├─ 单周视图 + 输入区   一周一屏，下面是这周的流水
 └─ 直接连 AI 厂商      用户自备 Key（可选）
        │ HTTPS + JWT
        ▼
Cloudflare Workers（workers-api/src/index.js，单文件）
 ├─ /auth/*      邮箱验证码登录、JWT
 ├─ /events/*    日程读写、软删除墓碑
 ├─ /asr         语音转写（代理 Workers AI Whisper）
 ├─ /events/ical iCal 订阅（推给手机系统日历）
 └─ /feedback    反馈
        │
        ▼
D1（SQLite）  users / events / verification_codes / cal_tokens / feedback / rate_limits
```

**同步是服务端权威**：时间戳一律服务端生成，客户端传的一律忽略。
本地写操作先进队列，断网时攒着，联网后自动补传。删除走墓碑，所以能跨设备传播。

---

## 数据模型

`events` 表的关键字段：

| 字段 | 说明 |
|---|---|
| `date` | 绝对日期 `YYYY-MM-DD`，唯一参与计算与显示 |
| `time` / `end_time` | 空串表示没有时间 |
| `title` | 描述。相对日期词在录入时剥离，不入库、不上界面 |
| `raw` | 原话全文，永不丢，只在编辑时展开 |
| `type` / `completed` | 内部语义，界面不暴露 |
| `date_confirmed` | 0 = 日期没认出来，界面提示用户确认 |
| `deleted_at` | 软删除墓碑，0 表示还活着 |
| `updated_at` | 服务端生成 |

---

## 目录

```
src/
  app/page.tsx        主界面（周视图 + 输入区 + 各弹窗）
  components/         WeekView（周视图）、InputArea（唯一输入入口）
  lib/                纯逻辑：日期解析、语音、队列、导入导出、CSV、XLSX 写入
  app/globals.css     视觉（森林背景 + 毛玻璃）
workers-api/
  src/index.js        后端单文件
  migrations/         SQL 迁移，按编号顺序执行
  scripts/migrate.mjs 迁移执行器（幂等）
tests/                单元测试
docs/                 产品说明与其它文档
agent/skills/         Agent 协作技能包
```

---

## 部署

```bash
# 后端
cd workers-api
npx wrangler secret put JWT_SECRET      # 至少 32 位随机串，务必先配
npm run migrate:remote
npm run deploy

# 前端
npm run build
npx wrangler pages deploy dist --project-name=schedule-pro --branch=main
```

> ⚠️ **项目名别搞错**：`schedule-pro` 才是菠萝日程的 Pages 项目
> （域名 `schedule.boluomate.com`）。
> `cabin-english-trainer` 是**公务英语 AI 陪练**那个 app 的项目
> （域名 `en.boluomate.com`）—— 名字里没有「schedule」，特别容易看串。
>
> 2026-11-06 就是因为照着旧文档写成了 `cabin-english-trainer`，
> 把菠萝日程的构建覆盖到了英语 app 上，害得重新部署了一遍才恢复。
>
> 部署前先确认：
>
> ```bash
> npx wrangler pages project list
> ```
>
> 另外 `schedule-pro` 项目**接了 GitHub 自动部署** ——
> `git push origin main` 会自己触发构建上线。
> 手动那条 `wrangler pages deploy` 只在需要立刻生效时用（比如构建参数要临时改）。
>
> `npx wrangler` 会去 npm registry 拉包，代理不稳时会 502。
> 项目里已经装了 wrangler，直接用本地的：
>
> ```bash
> ./workers-api/node_modules/.bin/wrangler pages deploy dist --project-name=schedule-pro --branch=main
> ```

### 必配的 secret

| 名称 | 用途 | 缺失的后果 |
|---|---|---|
| `JWT_SECRET` | 签发与校验登录令牌 | **不配会导致所有设备被登出**（每次冷启动密钥都变）。代码会打 `[FATAL]` 警告并用随机兜底密钥，登录状态不会保留 |
| `ADMIN_KEY` | 反馈管理页（`/?key=...`）的访问密钥 | 管理页返回 503，不会退回任何默认密码。这个页面原来用硬编码密码，已改为读 secret |
| `RESEND_API_KEY` | 发验证码邮件 | 登录不可用。失败时**不会**回传验证码，接口返回 `code_sent: false` |

> v4.0 已移除全部 AI 链路，`COZE_API_TOKEN` **不再需要**，
> 服务端的 `/ai/chat` 代理也已删除。`FAMILY_EMAILS` 仍保留但只影响
> 登录接口返回的 `role` 字段，不再改变任何行为。

Workers AI（语音转写）需要账号已开通，免费额度 10,000 Neurons/天，
Whisper 约 41.14 neurons/分钟，折合约 243 分钟音频/天。超额返回 429，
前端自动降级到浏览器语音识别，不影响可用性。

---

## 迁移说明

D1 的 SQLite **不支持** `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`。
所以迁移不要直接跑：

```bash
# 不要这样
npx wrangler d1 execute schedule_pro_db --remote --file=migrations/008_v4.0_data_model.sql
```

要用执行器，它负责跳过已应用的版本、探测列是否已存在：

```bash
cd workers-api && npm run migrate:remote
```

`001_v0.4.0.sql` 是破坏性重建（`DROP TABLE`），执行器按「`events` 表在不在」
判断：新库执行、旧库跳过。

---

## 部署前检查清单

- [ ] `wrangler secret put JWT_SECRET`（≥32 位随机串）
- [ ] `wrangler secret put RESEND_API_KEY`
- [ ] `cd workers-api && npm run migrate:remote`
- [ ] `npm run build` 通过
- [ ] `npm test` 全绿
- [ ] 真机点一次：记一条 → 刷新 → 还在；导出一个 Excel 能打开
- [ ] 真机点一次：课表 Excel 导入 → 预览能改 → 导入后日期时间正确

---

## 相关文档

| 文件 | 内容 |
|---|---|
| `docs/菠萝日程-v4.0-产品说明.md` | 产品定义、界面语言规范、技术方案、安全承诺、实施步骤与验证方案 |
| `工作日志.md` | 逐版本的改动记录与决策理由 |
| `AGENTS.md` / `CLAUDE.md` | Agent 协作规范索引 |
| `agent/skills/` | 代码评审、诊断、领域建模等技能包 |

---

## 许可

内部项目，非商业用途。
