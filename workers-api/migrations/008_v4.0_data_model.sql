-- 008_v4.0_data_model.sql — v4.0 数据模型扩展
--
-- 三件事：
--   1. events 加 date_confirmed（规则解析的待确认标记）
--   2. events 加 deleted_at（软删除墓碑，让删除能跨设备传播）
--   3. 建 schema_migrations 版本记录表，回填 001~007
--
-- 约束：
--   - 一律 ADD COLUMN / CREATE TABLE IF NOT EXISTS，绝不重建表。
--     001 是破坏性重建（DROP TABLE），那是 v0.4.0 当时的架构重写；
--     现在的生产库有真实数据，重建会全丢。
--
-- 幂等性说明（D1 实测结论）：
--   D1 的 SQLite **不支持 ALTER TABLE ... ADD COLUMN IF NOT EXISTS**
--   （实测报 SQLITE_ERROR: near "EXISTS"）。
--   因此本文件不做「重复执行不报错」的自我保护，改为：
--     - CREATE TABLE / CREATE INDEX 用 IF NOT EXISTS（这两类 D1 支持）
--     - 两处 ALTER TABLE ADD COLUMN 由迁移执行器负责幂等：
--       执行前用 pragma_table_info 探测列是否已存在，存在则跳过。
--   执行器：workers-api/scripts/migrate.mjs
--
--   ⚠️ 不要直接 `wrangler d1 execute --file=008_*.sql`，
--      那样第二次执行会在 ALTER TABLE 处报错。用 migrate.mjs。

-- ---------- 1. 迁移版本记录表 ----------
-- 此前迁移状态靠人记，多一人部署就可能重复执行 ALTER 而报错。
CREATE TABLE IF NOT EXISTS schema_migrations (
  version TEXT PRIMARY KEY,
  applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 回填已执行过的迁移（001~007 是历史事实，不重跑，只登记）
INSERT OR IGNORE INTO schema_migrations (version) VALUES
  ('001_v0.4.0'),
  ('002_cal_tokens'),
  ('003_feedback'),
  ('004_tasks'),
  ('005_rate_limits'),
  ('006_location_people'),
  ('007_end_time');

-- 登记本迁移自身
INSERT OR IGNORE INTO schema_migrations (version) VALUES ('008_v4.0_data_model');

-- ---------- 2. events 新增字段 ----------
-- date_confirmed：0 = 规则没解出日期、待用户确认；1 = 已确认。
-- 默认 1 —— 存量数据都是人工导入或已确认的，不能因为加字段就全部变成待确认。
ALTER TABLE events ADD COLUMN date_confirmed INTEGER NOT NULL DEFAULT 1;

-- deleted_at：软删除墓碑的时间戳，0 表示未删除。
-- 第 7 步的同步改造靠它让删除跨设备传播；加字段时存量全部为 0（未删除），符合预期。
ALTER TABLE events ADD COLUMN deleted_at INTEGER NOT NULL DEFAULT 0;

-- ---------- 3. 索引 ----------
-- 拉取未删除项是最高频查询：WHERE user_id = ? AND deleted_at = 0
-- 现有 idx_events_user_date(user_id, date) 仍能命中主查询，
-- 这条索引专门覆盖"按用户取全部未删（含按 updated_at 增量比对）"的形态。
CREATE INDEX IF NOT EXISTS idx_events_user_deleted ON events(user_id, deleted_at);
