CREATE TABLE quick_links (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),path TEXT NOT NULL UNIQUE,
 metadata JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
