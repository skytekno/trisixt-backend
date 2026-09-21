CREATE TABLE mcp_clients (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), name TEXT NOT NULL, redirect_uris JSONB NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE mcp_authorization_codes (
 code_hash TEXT PRIMARY KEY, client_id UUID NOT NULL REFERENCES mcp_clients(id) ON DELETE CASCADE,
 user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE, redirect_uri TEXT NOT NULL,
 challenge TEXT NOT NULL, scope TEXT NOT NULL, issuer TEXT NOT NULL, audience TEXT NOT NULL,
 project_ids UUID[] NOT NULL, expires_at TIMESTAMPTZ NOT NULL, used_at TIMESTAMPTZ,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE mcp_tokens (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), family_id UUID NOT NULL,
 client_id UUID NOT NULL REFERENCES mcp_clients(id) ON DELETE CASCADE,
 user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 access_hash TEXT NOT NULL UNIQUE, refresh_hash TEXT NOT NULL UNIQUE,
 scope TEXT NOT NULL, issuer TEXT NOT NULL, audience TEXT NOT NULL, project_ids UUID[] NOT NULL,
 expires_at TIMESTAMPTZ NOT NULL, refresh_expires_at TIMESTAMPTZ NOT NULL,
 revoked_at TIMESTAMPTZ, last_used_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX mcp_token_user ON mcp_tokens(user_id);
CREATE INDEX mcp_token_family ON mcp_tokens(family_id);
CREATE TABLE mcp_usage (
 token_id UUID NOT NULL REFERENCES mcp_tokens(id) ON DELETE CASCADE,
 day DATE NOT NULL DEFAULT current_date, requests BIGINT NOT NULL DEFAULT 1,
 PRIMARY KEY(token_id,day)
);
