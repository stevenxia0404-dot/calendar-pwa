-- 005_rate_limits: 限流表
CREATE TABLE rate_limits (
  ip TEXT NOT NULL,
  timestamp INTEGER NOT NULL
);
CREATE INDEX idx_rate_limits_ip_ts ON rate_limits(ip, timestamp);
