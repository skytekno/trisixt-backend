CREATE TABLE migration_sources(
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),project_id UUID NOT NULL UNIQUE REFERENCES projects(id) ON DELETE CASCADE,
 provider TEXT NOT NULL CHECK(provider IN('branch','appsflyer','firebase')),old_host TEXT NOT NULL UNIQUE,
 provider_hosted BOOLEAN NOT NULL DEFAULT false,credentials_ciphertext TEXT NOT NULL,enabled BOOLEAN NOT NULL DEFAULT true,
 consecutive_failures INTEGER NOT NULL DEFAULT 0,first_failure_at TIMESTAMPTZ,last_error_status INTEGER,
 auto_disabled_at TIMESTAMPTZ,degraded_email_sent_at TIMESTAMPTZ,created_at TIMESTAMPTZ NOT NULL DEFAULT now(),updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE migration_hosts(hostname TEXT PRIMARY KEY,source_id UUID NOT NULL REFERENCES migration_sources(id) ON DELETE CASCADE);
CREATE TABLE migrated_links(source_id UUID NOT NULL REFERENCES migration_sources(id) ON DELETE CASCADE,old_path TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN('resolved','not_found','transient_error')),link_id UUID REFERENCES links(id) ON DELETE SET NULL,cached_until TIMESTAMPTZ,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),PRIMARY KEY(source_id,old_path));
CREATE TABLE migration_jobs(id UUID PRIMARY KEY DEFAULT gen_random_uuid(),source_id UUID NOT NULL REFERENCES migration_sources(id) ON DELETE CASCADE,old_path TEXT NOT NULL,
 attempts INTEGER NOT NULL DEFAULT 0,available_at TIMESTAMPTZ NOT NULL DEFAULT now(),finished_at TIMESTAMPTZ,last_error TEXT,UNIQUE(source_id,old_path));
CREATE TABLE migration_alerts(id UUID PRIMARY KEY DEFAULT gen_random_uuid(),source_id UUID NOT NULL REFERENCES migration_sources(id) ON DELETE CASCADE,
 kind TEXT NOT NULL,payload JSONB NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT now(),delivered_at TIMESTAMPTZ);
CREATE FUNCTION trisixt_remove_hostname_migration() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 DELETE FROM migration_sources WHERE project_id=OLD.project_id AND old_host=OLD.hostname AND NOT provider_hosted;RETURN OLD;END $$;
CREATE TRIGGER cleanup_hostname_migration AFTER DELETE ON custom_hostnames FOR EACH ROW EXECUTE FUNCTION trisixt_remove_hostname_migration();
