CREATE TABLE browser_sessions (
 token_hash TEXT PRIMARY KEY,
 project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 visitor_id UUID NOT NULL,
 expires_at TIMESTAMPTZ NOT NULL,
 FOREIGN KEY(project_id,visitor_id) REFERENCES visitors(project_id,id) ON DELETE CASCADE
);
CREATE INDEX browser_sessions_expiry ON browser_sessions(expires_at);
