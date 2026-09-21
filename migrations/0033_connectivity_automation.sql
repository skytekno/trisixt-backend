CREATE TABLE instance_api_keys (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),instance_id UUID NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
 token_hash TEXT NOT NULL UNIQUE,name TEXT NOT NULL DEFAULT 'Server SDK', created_at TIMESTAMPTZ NOT NULL DEFAULT now(), revoked_at TIMESTAMPTZ
);
CREATE TABLE automation_key_usage (
 key_id UUID NOT NULL REFERENCES instance_api_keys(id) ON DELETE CASCADE, day DATE NOT NULL DEFAULT current_date,
 PRIMARY KEY(key_id,day)
);
