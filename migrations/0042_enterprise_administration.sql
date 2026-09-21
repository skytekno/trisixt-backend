ALTER TABLE instance_sso ADD COLUMN enforced BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE instance_sso ADD COLUMN jit_provision BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE instance_sso ADD COLUMN admin_claim_value TEXT;
CREATE TABLE instance_sso_domains (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 instance_id UUID NOT NULL REFERENCES instance_sso(instance_id) ON DELETE CASCADE,
 domain TEXT NOT NULL,
 verification_token TEXT NOT NULL,
 verified_at TIMESTAMPTZ,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 UNIQUE(instance_id,domain)
);
CREATE UNIQUE INDEX sso_domain_verified_unique ON instance_sso_domains(domain) WHERE verified_at IS NOT NULL;
CREATE TABLE audit_export_tokens (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 instance_id UUID NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
 created_by UUID REFERENCES users(id) ON DELETE SET NULL,
 name TEXT NOT NULL CHECK(char_length(name) BETWEEN 1 AND 255),
 token_hash TEXT NOT NULL UNIQUE,
 last_used_at TIMESTAMPTZ,
 revoked_at TIMESTAMPTZ,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
