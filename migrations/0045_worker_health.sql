CREATE TABLE worker_job_health (
 name TEXT PRIMARY KEY,
 last_attempt_at TIMESTAMPTZ NOT NULL,
 last_success_at TIMESTAMPTZ,
 last_error TEXT
);
