-- Native Rust domain schema. Tenant references include project_id to prevent
-- accidental cross-project relations even if an application check is missed.
CREATE UNIQUE INDEX users_email_ci ON users (lower(email));
UPDATE access_tokens SET expires_at = created_at + interval '30 days' WHERE expires_at IS NULL;
ALTER TABLE access_tokens ALTER COLUMN expires_at SET NOT NULL;
ALTER TABLE projects ADD COLUMN name TEXT NOT NULL DEFAULT 'Project';
CREATE UNIQUE INDEX projects_domain_unique ON projects (lower(domain));

CREATE TABLE auth_attempts (
    email_hash TEXT PRIMARY KEY,
    attempts INTEGER NOT NULL DEFAULT 1,
    window_start TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE project_api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ
);
CREATE INDEX project_api_keys_project ON project_api_keys(project_id);

CREATE TABLE campaigns (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
    metadata JSONB NOT NULL DEFAULT '{}',
    archived_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(project_id,id)
);
CREATE INDEX campaigns_project ON campaigns(project_id,created_at);

CREATE TABLE links (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    campaign_id UUID,
    name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
    path TEXT NOT NULL CHECK (path ~ '^[a-zA-Z0-9_-]{1,100}$'),
    target_url TEXT NOT NULL,
    ios_url TEXT,
    android_url TEXT,
    metadata JSONB NOT NULL DEFAULT '{}',
    archived_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(project_id,id),
    UNIQUE(project_id,path),
    FOREIGN KEY(project_id,campaign_id) REFERENCES campaigns(project_id,id)
);
CREATE INDEX links_project ON links(project_id,created_at);

CREATE TABLE visitors (
    id UUID NOT NULL,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    external_id TEXT,
    attributes JSONB NOT NULL DEFAULT '{}',
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY(project_id,id)
);
CREATE INDEX visitors_project_last_seen ON visitors(project_id,last_seen_at DESC);

CREATE TABLE events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id UUID NOT NULL,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    visitor_id UUID NOT NULL,
    event_type TEXT NOT NULL CHECK (char_length(event_type) BETWEEN 1 AND 100),
    properties JSONB NOT NULL DEFAULT '{}',
    occurred_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(project_id,event_id),
    FOREIGN KEY(project_id,visitor_id) REFERENCES visitors(project_id,id)
);
CREATE INDEX events_project_time ON events(project_id,occurred_at DESC);
CREATE INDEX events_visitor ON events(project_id,visitor_id,occurred_at DESC);

CREATE TABLE analytics_outbox (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    event_id UUID NOT NULL UNIQUE REFERENCES events(id) ON DELETE CASCADE,
    payload JSONB NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    available_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    processed_at TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX analytics_outbox_pending ON analytics_outbox(available_at,created_at) WHERE processed_at IS NULL;
