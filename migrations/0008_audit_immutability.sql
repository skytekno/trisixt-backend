-- Application audit history is append-only. Database administrators still control
-- DDL and backups; the hash chain detects edits, it is not a substitute for them.
CREATE FUNCTION trisixt_audit_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'audit history is append-only' USING ERRCODE='42501';
END $$;
CREATE TRIGGER audit_immutable BEFORE UPDATE OR DELETE ON audit_events
FOR EACH ROW EXECUTE FUNCTION trisixt_audit_immutable();
CREATE TRIGGER audit_no_truncate BEFORE TRUNCATE ON audit_events
FOR EACH STATEMENT EXECUTE FUNCTION trisixt_audit_immutable();
