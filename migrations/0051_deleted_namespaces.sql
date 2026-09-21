-- No foreign keys: deletion work must survive the relational cascade.
CREATE TABLE deleted_namespaces (
 namespace_id UUID PRIMARY KEY,
 kind TEXT NOT NULL CHECK(kind IN ('project','instance')),
 deleted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 available_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 attempts BIGINT NOT NULL DEFAULT 0,
 storage_cleaned_at TIMESTAMPTZ,
 warehouse_cleaned_at TIMESTAMPTZ,
 last_success_at TIMESTAMPTZ,
 last_error TEXT
);
CREATE INDEX deleted_namespaces_due ON deleted_namespaces(available_at,namespace_id);
CREATE FUNCTION trisixt_deleted_namespace() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 INSERT INTO deleted_namespaces(namespace_id,kind) VALUES(OLD.id,TG_ARGV[0]) ON CONFLICT(namespace_id) DO NOTHING;
 RETURN OLD;
END $$;
CREATE TRIGGER project_deletion_cleanup BEFORE DELETE ON projects FOR EACH ROW EXECUTE FUNCTION trisixt_deleted_namespace('project');
CREATE TRIGGER instance_deletion_cleanup BEFORE DELETE ON instances FOR EACH ROW EXECUTE FUNCTION trisixt_deleted_namespace('instance');
CREATE FUNCTION trisixt_reject_retired_namespace() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM deleted_namespaces WHERE namespace_id=NEW.id) THEN
  RAISE EXCEPTION 'identifier has been retired' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER project_retired_identifier BEFORE INSERT ON projects FOR EACH ROW EXECUTE FUNCTION trisixt_reject_retired_namespace();
CREATE TRIGGER instance_retired_identifier BEFORE INSERT ON instances FOR EACH ROW EXECUTE FUNCTION trisixt_reject_retired_namespace();
