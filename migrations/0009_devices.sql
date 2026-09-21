CREATE TABLE devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    visitor_id UUID NOT NULL,
    platform TEXT NOT NULL DEFAULT 'other',
    push_token TEXT,
    push_environment TEXT NOT NULL DEFAULT 'production' CHECK(push_environment IN ('test','production')),
    vendor_id TEXT,
    user_agent TEXT NOT NULL DEFAULT '',
    app_version TEXT NOT NULL DEFAULT '',
    build TEXT NOT NULL DEFAULT '',
    language TEXT NOT NULL DEFAULT '',
    model TEXT NOT NULL DEFAULT '',
    timezone TEXT NOT NULL DEFAULT 'UTC',
    screen_height INTEGER,
    screen_width INTEGER,
    webgl_renderer TEXT,
    webgl_vendor TEXT,
    ip INET,
    attributes JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(project_id,id),
    FOREIGN KEY(project_id,visitor_id) REFERENCES visitors(project_id,id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX devices_vendor ON devices(project_id,vendor_id) WHERE vendor_id IS NOT NULL AND vendor_id<>'';
CREATE INDEX devices_visitor ON devices(project_id,visitor_id,updated_at DESC);
CREATE INDEX devices_push ON devices(project_id,platform) WHERE push_token IS NOT NULL;
