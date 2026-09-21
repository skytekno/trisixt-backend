-- Enterprise capabilities are part of the core schema, not a licensed add-on.
CREATE TABLE audit_events (
    instance_id UUID NOT NULL,
    sequence BIGINT NOT NULL,
    actor_id UUID,
    action TEXT NOT NULL,
    target_id UUID,
    details JSONB NOT NULL DEFAULT '{}',
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    previous_hash TEXT NOT NULL,
    hash TEXT NOT NULL,
    PRIMARY KEY(instance_id,sequence)
);

CREATE FUNCTION trisixt_audit(p_instance UUID,p_actor UUID,p_action TEXT,p_target UUID,p_details JSONB)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE seq BIGINT; prev TEXT; stamp TIMESTAMPTZ := clock_timestamp(); body JSONB;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended(p_instance::text,0));
  SELECT sequence,hash INTO seq,prev FROM audit_events WHERE instance_id=p_instance ORDER BY sequence DESC LIMIT 1;
  seq:=coalesce(seq,0)+1; prev:=coalesce(prev,repeat('0',64));
  body:=jsonb_build_object('instance_id',p_instance,'sequence',seq,'actor_id',p_actor,'action',p_action,'target_id',p_target,'details',p_details,'occurred_at',stamp);
  INSERT INTO audit_events(instance_id,sequence,actor_id,action,target_id,details,occurred_at,previous_hash,hash)
  VALUES(p_instance,seq,p_actor,p_action,p_target,p_details,stamp,prev,encode(sha256(convert_to(prev||body::text,'UTF8')),'hex'));
END $$;

CREATE FUNCTION trisixt_audit_domain_change() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE data JSONB; tenant UUID; target UUID;
BEGIN
  IF TG_OP='DELETE' THEN data:=to_jsonb(OLD); ELSE data:=to_jsonb(NEW); END IF;
  target:=(data->>'id')::uuid;
  IF TG_TABLE_NAME='instances' THEN tenant:=target;
  ELSIF data ? 'instance_id' THEN tenant:=(data->>'instance_id')::uuid;
  ELSE SELECT instance_id INTO tenant FROM projects WHERE id=(data->>'project_id')::uuid;
  END IF;
  IF tenant IS NOT NULL THEN
    PERFORM trisixt_audit(tenant,nullif(current_setting('trisixt.actor_id',true),'')::uuid,
      TG_TABLE_NAME||'.'||lower(TG_OP),target,
      jsonb_strip_nulls(jsonb_build_object('name',data->'name','role',data->'role','user_id',data->'user_id','project_id',data->'project_id')));
  END IF;
  IF TG_OP='DELETE' THEN RETURN OLD; END IF; RETURN NEW;
END $$;
CREATE TRIGGER audit_instances AFTER INSERT OR UPDATE OR DELETE ON instances FOR EACH ROW EXECUTE FUNCTION trisixt_audit_domain_change();
CREATE TRIGGER audit_projects AFTER INSERT OR UPDATE OR DELETE ON projects FOR EACH ROW EXECUTE FUNCTION trisixt_audit_domain_change();
CREATE TRIGGER audit_roles AFTER INSERT OR UPDATE OR DELETE ON instance_roles FOR EACH ROW EXECUTE FUNCTION trisixt_audit_domain_change();
CREATE TRIGGER audit_campaigns AFTER INSERT OR UPDATE OR DELETE ON campaigns FOR EACH ROW EXECUTE FUNCTION trisixt_audit_domain_change();
CREATE TRIGGER audit_links AFTER INSERT OR UPDATE OR DELETE ON links FOR EACH ROW EXECUTE FUNCTION trisixt_audit_domain_change();

CREATE TABLE scim_tokens (
    instance_id UUID PRIMARY KEY REFERENCES instances(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE scim_users (
    instance_id UUID NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    external_id TEXT,
    display_name TEXT NOT NULL DEFAULT '',
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY(instance_id,user_id),
    UNIQUE(user_id),
    UNIQUE(instance_id,external_id)
);
