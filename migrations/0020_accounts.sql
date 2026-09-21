ALTER TABLE users ADD COLUMN credential_version BIGINT NOT NULL DEFAULT 0;
CREATE FUNCTION trisixt_account_credential_version() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF OLD.password_hash IS DISTINCT FROM NEW.password_hash OR OLD.otp_enabled IS DISTINCT FROM NEW.otp_enabled THEN NEW.credential_version:=OLD.credential_version+1; END IF; RETURN NEW; END $$;
ALTER TABLE users ADD COLUMN name TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN invitation_pending BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN email_confirmed_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN otp_enabled BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN otp_secret_encrypted TEXT;
ALTER TABLE users ADD COLUMN otp_last_counter BIGINT;
CREATE TRIGGER account_credential_version BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION trisixt_account_credential_version();

CREATE TABLE refresh_sessions (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 family_id UUID NOT NULL,
 auth_method TEXT NOT NULL DEFAULT 'password' CHECK(auth_method IN ('password','oidc')),
 token_hash TEXT UNIQUE NOT NULL,
 access_token_id UUID REFERENCES access_tokens(id) ON DELETE SET NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 expires_at TIMESTAMPTZ NOT NULL DEFAULT now()+interval '7 days',
 consumed_at TIMESTAMPTZ,
 revoked_at TIMESTAMPTZ
);
CREATE INDEX refresh_sessions_family ON refresh_sessions(family_id);
CREATE INDEX refresh_sessions_user ON refresh_sessions(user_id);
CREATE TABLE account_tokens (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 purpose TEXT NOT NULL CHECK(purpose IN ('reset','invite','confirm')),
 token_hash TEXT NOT NULL UNIQUE,
 instance_id UUID REFERENCES instances(id) ON DELETE CASCADE,
 invited_role TEXT CHECK(invited_role IN ('admin','member')),
 expires_at TIMESTAMPTZ NOT NULL,
 used_at TIMESTAMPTZ,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX account_tokens_user ON account_tokens(user_id,purpose);
CREATE TABLE otp_recovery_codes (
 user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 code_hash TEXT NOT NULL,
 used_at TIMESTAMPTZ,
 PRIMARY KEY(user_id,code_hash)
);
CREATE TABLE mail_outbox (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 payload_encrypted TEXT NOT NULL,
 dedup_key TEXT UNIQUE,
 source_type TEXT,
 source_ref TEXT,
 attempts INTEGER NOT NULL DEFAULT 0,
 available_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 lease_id UUID,
 lease_until TIMESTAMPTZ,
 sent_at TIMESTAMPTZ,
 last_error TEXT,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX mail_outbox_pending ON mail_outbox(available_at) WHERE sent_at IS NULL;
