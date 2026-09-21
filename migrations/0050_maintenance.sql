CREATE TABLE retention_jobs (
 project_id UUID PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
 available_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 attempts INTEGER NOT NULL DEFAULT 0,
 last_completed_at TIMESTAMPTZ,
 cutoff TIMESTAMPTZ,
 deleted_events BIGINT NOT NULL DEFAULT 0,
 last_error TEXT
);
CREATE TABLE maintenance_schedules (
 name TEXT PRIMARY KEY,
 available_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 last_completed_at TIMESTAMPTZ,
 result JSONB NOT NULL DEFAULT '{}'
);
INSERT INTO maintenance_schedules(name) VALUES('expired_records');
