-- SSO providers are selected from the operator's allowlist, not arbitrary tenant URLs.
CREATE TABLE instance_sso (
    instance_id UUID PRIMARY KEY REFERENCES instances(id) ON DELETE CASCADE,
    provider_key TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT true,
    version UUID NOT NULL DEFAULT gen_random_uuid(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE oidc_identities (
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY(issuer,subject)
);
CREATE INDEX oidc_identities_user ON oidc_identities(user_id);
CREATE TABLE oidc_transactions (
    state_hash TEXT PRIMARY KEY,
    browser_hash TEXT NOT NULL,
    instance_id UUID NOT NULL REFERENCES instance_sso(instance_id) ON DELETE CASCADE,
    config_version UUID NOT NULL,
    nonce TEXT NOT NULL,
    pkce_verifier TEXT NOT NULL,
    binding_user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    binding_token_hash TEXT,
    expires_at TIMESTAMPTZ NOT NULL DEFAULT now() + interval '10 minutes',
    CHECK ((binding_user_id IS NULL) = (binding_token_hash IS NULL))
);
CREATE INDEX oidc_transactions_expiry ON oidc_transactions(expires_at);
