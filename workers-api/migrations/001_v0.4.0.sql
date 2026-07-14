-- v0.4.0 D1 数据库迁移
-- users: github_id/username/avatar_url → email
-- 新增: verification_codes 表
-- events: 加 updated_at 字段和索引

-- 1. 重建 users 表
DROP TABLE IF EXISTS users;
CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 2. 重建 events 表（id 改为 TEXT UUID）
DROP TABLE IF EXISTS events;
CREATE TABLE events (
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  date TEXT NOT NULL,
  time TEXT NOT NULL,
  raw TEXT DEFAULT '',
  updated_at INTEGER NOT NULL DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX idx_events_user_date ON events(user_id, date);
CREATE INDEX idx_events_user_updated ON events(user_id, updated_at);

-- 3. 验证码表
CREATE TABLE verification_codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL,
  code TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_vc_email ON verification_codes(email);
