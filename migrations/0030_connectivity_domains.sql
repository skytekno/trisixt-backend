CREATE TABLE project_domains (
 project_id UUID PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
 generic_title TEXT NOT NULL DEFAULT 'Trisixt', generic_subtitle TEXT NOT NULL DEFAULT '',
 generic_image_url TEXT, google_tracking_id TEXT, active_custom_host TEXT,
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE custom_hostnames (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 hostname TEXT NOT NULL UNIQUE, purpose TEXT NOT NULL CHECK(purpose IN('primary','migration')),
 source TEXT NOT NULL CHECK(source IN('enterprise','saas')), mode TEXT NOT NULL CHECK(mode IN('manual','cloudflare')),
 status TEXT NOT NULL CHECK(status IN('provisioning','pending','active','suspended','failed')),
 cf_id TEXT, ssl_status TEXT, ssl_method TEXT, validation_records JSONB NOT NULL DEFAULT '[]', ownership_verification JSONB,
 verification_errors TEXT, grace_until TIMESTAMPTZ, activated_at TIMESTAMPTZ, last_checked_at TIMESTAMPTZ,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 UNIQUE(project_id,purpose)
);
CREATE INDEX custom_hostnames_maintenance ON custom_hostnames(status,last_checked_at);
CREATE TABLE connectivity_rate_limits(bucket TEXT PRIMARY KEY,attempts INTEGER NOT NULL,expires_at TIMESTAMPTZ NOT NULL);
CREATE TABLE domain_preflight_cache(project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,hostname TEXT NOT NULL,result JSONB NOT NULL,expires_at TIMESTAMPTZ NOT NULL,PRIMARY KEY(project_id,hostname));
