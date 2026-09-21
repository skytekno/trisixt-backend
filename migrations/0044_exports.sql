CREATE TABLE export_jobs (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 instance_id UUID NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
 project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
 user_id UUID REFERENCES users(id) ON DELETE SET NULL,
 kind TEXT NOT NULL CHECK(kind IN('links','usage')),
 parameters JSONB NOT NULL,
 state TEXT NOT NULL DEFAULT 'queued' CHECK(state IN('queued','running','ready','failed','expired')),
 cursor_id UUID,
 row_count BIGINT NOT NULL DEFAULT 0,
 parts JSONB NOT NULL DEFAULT '[]',
 attempts INTEGER NOT NULL DEFAULT 0,
 available_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 lease_id UUID,
 lease_until TIMESTAMPTZ,
 last_error TEXT,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 expires_at TIMESTAMPTZ NOT NULL DEFAULT now()+interval '24 hours'
);
CREATE INDEX export_jobs_pending ON export_jobs(available_at) WHERE state IN('queued','running');
