-- 004_tasks: 添加 task 类型和完成状态
ALTER TABLE events ADD COLUMN type TEXT NOT NULL DEFAULT 'event';
ALTER TABLE events ADD COLUMN completed INTEGER NOT NULL DEFAULT 0;
