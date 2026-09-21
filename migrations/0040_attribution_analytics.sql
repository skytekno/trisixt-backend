CREATE TABLE visitor_aliases (
 project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 alias_id UUID NOT NULL,
 visitor_id UUID NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 PRIMARY KEY(project_id,alias_id),
 CHECK(alias_id<>visitor_id),
 FOREIGN KEY(project_id,alias_id) REFERENCES visitors(project_id,id) ON DELETE CASCADE,
 FOREIGN KEY(project_id,visitor_id) REFERENCES visitors(project_id,id) ON DELETE CASCADE
);
CREATE TABLE visitor_attributions (
 project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 visitor_id UUID NOT NULL,
 link_id UUID,
 campaign_id UUID,
 source TEXT,
 medium TEXT,
 attributed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 method TEXT NOT NULL,
 metadata JSONB NOT NULL DEFAULT '{}',
 PRIMARY KEY(project_id,visitor_id),
 FOREIGN KEY(project_id,visitor_id) REFERENCES visitors(project_id,id) ON DELETE CASCADE,
 FOREIGN KEY(project_id,link_id) REFERENCES links(project_id,id) ON DELETE SET NULL(link_id),
 FOREIGN KEY(project_id,campaign_id) REFERENCES campaigns(project_id,id) ON DELETE SET NULL(campaign_id)
);
CREATE TABLE link_clicks (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 link_id UUID NOT NULL,
 visitor_id UUID NOT NULL,
 device_id UUID,
 fingerprint TEXT,
 clipboard_hash TEXT NOT NULL UNIQUE,
 platform TEXT NOT NULL,
 handled_at TIMESTAMPTZ,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 FOREIGN KEY(project_id,link_id) REFERENCES links(project_id,id) ON DELETE CASCADE,
 FOREIGN KEY(project_id,visitor_id) REFERENCES visitors(project_id,id) ON DELETE CASCADE,
 FOREIGN KEY(project_id,device_id) REFERENCES devices(project_id,id) ON DELETE SET NULL(device_id)
);
CREATE INDEX link_clicks_fingerprint ON link_clicks(project_id,fingerprint,created_at DESC) WHERE handled_at IS NULL;
CREATE TABLE screen_aliases (
 project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 identifier TEXT NOT NULL CHECK(char_length(identifier) BETWEEN 1 AND 255),
 name TEXT NOT NULL CHECK(char_length(name) BETWEEN 1 AND 255),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 PRIMARY KEY(project_id,identifier)
);
ALTER TABLE instances ADD COLUMN cold_storage_days INTEGER NOT NULL DEFAULT 365 CHECK(cold_storage_days BETWEEN 1 AND 3650);
ALTER TABLE instances ADD COLUMN delete_days INTEGER NOT NULL DEFAULT 730 CHECK(delete_days BETWEEN 1 AND 3650);
ALTER TABLE instances ADD COLUMN setup_progress JSONB NOT NULL DEFAULT '{}';

-- PostgreSQL's canonical event ledger drives precise explorer, retention and
-- session reads for both warehouse choices; immutable outbox events still feed
-- ClickHouse or Pub/Sub->BigQuery. No transient warehouse delivery lag is exposed
-- as a false zero in these responses.
CREATE FUNCTION trisixt_uuid(value TEXT) RETURNS UUID LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE AS $$
BEGIN RETURN value::uuid; EXCEPTION WHEN invalid_text_representation THEN RETURN NULL; END $$;
CREATE VIEW analytics_event_facts AS
SELECT e.id,e.event_id,e.project_id,coalesce(va.visitor_id,e.visitor_id) AS visitor_id,
 e.visitor_id AS original_visitor_id,e.event_type,e.occurred_at,e.created_at,e.properties,
 coalesce(e.properties->>'event_name',e.event_type) AS event_name,
 coalesce(e.properties->>'ads_platform','') AS ads_platform,
 trisixt_uuid(e.properties->>'_device_id') AS device_id,
 CASE WHEN jsonb_typeof(e.properties->'engagement_time')='number' THEN greatest(0,least(86400000,(e.properties->>'engagement_time')::numeric))::double precision ELSE 0 END AS engagement_time,
 CASE WHEN e.properties->>'platform' IN ('mac','windows','linux','desktop') THEN 'web' ELSE coalesce(e.properties->>'platform','other') END AS platform,
 coalesce(e.properties->>'app_version','') AS app_version,
 coalesce(e.properties->>'session_id','') AS session_id,
 coalesce(e.properties->>'screen_name','') AS screen_name,
 coalesce(e.properties->>'country','') AS country,
 coalesce(e.properties->>'city','') AS city,
 coalesce(e.properties->>'device_model','') AS device_model,
 coalesce(e.properties->>'os','') AS os,
 coalesce(e.properties->>'os_version','') AS os_version,
 CASE WHEN e.properties ? '_sdk_identifier' THEN coalesce(e.properties->>'_sdk_identifier','') ELSE coalesce(v.external_id,'') END AS sdk_identifier,
 coalesce(e.properties->'_user_attributes',v.attributes) AS user_attributes,
 CASE WHEN e.properties ? '_attribution' THEN trisixt_uuid(e.properties#>>'{_attribution,link_id}') ELSE l.id END AS link_id,
 CASE WHEN e.properties ? '_attribution' THEN trisixt_uuid(e.properties#>>'{_attribution,campaign_id}') ELSE c.id END AS campaign_id,
 coalesce(e.properties->>'tracking_source','') AS tracking_source,
 coalesce(e.properties->>'tracking_medium','') AS tracking_medium,
 coalesce(e.properties->>'tracking_campaign','') AS tracking_campaign,
 CASE WHEN (e.properties ? '_attribution' AND trisixt_uuid(e.properties#>>'{_attribution,campaign_id}') IS NOT NULL) OR (NOT e.properties ? '_attribution' AND c.id IS NOT NULL) THEN 'campaigns'
      WHEN e.properties#>>'{_attribution,sdk_generated}'='true' AND e.properties#>>'{_attribution,link_visitor_id}' IS NOT NULL THEN 'referrals'
      WHEN e.properties#>>'{_attribution,sdk_generated}'='true' THEN 'api_links'
      WHEN (e.properties ? '_attribution' AND trisixt_uuid(e.properties#>>'{_attribution,link_id}') IS NOT NULL) OR (NOT e.properties ? '_attribution' AND l.id IS NOT NULL) THEN 'links' ELSE 'organic' END AS source,
 v.first_seen_at
FROM events e
LEFT JOIN visitor_aliases va ON va.project_id=e.project_id AND va.alias_id=e.visitor_id
JOIN visitors v ON v.project_id=e.project_id AND v.id=coalesce(va.visitor_id,e.visitor_id)
LEFT JOIN links l ON l.project_id=e.project_id AND l.id::text=e.properties->>'link_id'
LEFT JOIN campaigns c ON c.project_id=e.project_id AND c.id::text=CASE WHEN e.properties ? '_attribution' THEN e.properties#>>'{_attribution,campaign_id}' ELSE coalesce(e.properties->>'campaign_id',l.campaign_id::text) END;

CREATE FUNCTION trisixt_matches_filters(row_data JSONB, filters JSONB) RETURNS BOOLEAN
LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE AS $$
DECLARE f JSONB; actual JSONB; expected JSONB; field_name TEXT; op TEXT; result BOOLEAN;
BEGIN
 FOR f IN SELECT value FROM jsonb_array_elements(filters) LOOP
  field_name:=f->>'field'; op:=f->>'operator'; expected:=f->'value';
  IF field_name LIKE 'user.%' THEN actual:=coalesce(row_data->'user_attributes'->substring(field_name FROM 6),(row_data->'user_attributes') #> string_to_array(substring(field_name FROM 6),'.'));
  ELSIF field_name LIKE 'properties.%' THEN actual:=coalesce(row_data->'properties'->substring(field_name FROM 12),(row_data->'properties') #> string_to_array(substring(field_name FROM 12),'.'));
  ELSE actual:=row_data->field_name; END IF;
  IF (field_name LIKE 'user.%' OR field_name LIKE 'properties.%') AND op IN ('eq','neq','in','not_in') THEN
   IF op IN ('eq','neq') THEN
    result:=(actual#>>'{}') IS NOT DISTINCT FROM (expected#>>'{}');
    IF op='neq' THEN result:=NOT result; END IF;
   ELSE
    SELECT EXISTS(SELECT 1 FROM jsonb_array_elements(expected) value WHERE (value#>>'{}') IS NOT DISTINCT FROM (actual#>>'{}')) INTO result;
    IF op='not_in' THEN result:=NOT result; END IF;
   END IF;
   IF NOT result THEN RETURN false; END IF;
   CONTINUE;
  END IF;
  result:=CASE op
   WHEN 'eq' THEN actual=expected WHEN 'neq' THEN actual IS DISTINCT FROM expected
   WHEN 'in' THEN expected @> jsonb_build_array(actual)
   WHEN 'not_in' THEN NOT expected @> jsonb_build_array(actual)
   WHEN 'contains' THEN strpos(lower(coalesce(actual#>>'{}','')),lower(expected#>>'{}'))>0
   WHEN 'not_contains' THEN strpos(lower(coalesce(actual#>>'{}','')),lower(expected#>>'{}'))=0
   WHEN 'starts_with' THEN starts_with(lower(coalesce(actual#>>'{}','')),lower(expected#>>'{}'))
   WHEN 'is_set' THEN actual IS NOT NULL AND actual<>'null'::jsonb
   WHEN 'is_not_set' THEN actual IS NULL OR actual='null'::jsonb
   WHEN 'gt' THEN CASE WHEN jsonb_typeof(actual)='number' AND jsonb_typeof(expected)='number' THEN (actual#>>'{}')::numeric>(expected#>>'{}')::numeric ELSE false END
   WHEN 'gte' THEN CASE WHEN jsonb_typeof(actual)='number' AND jsonb_typeof(expected)='number' THEN (actual#>>'{}')::numeric>=(expected#>>'{}')::numeric ELSE false END
   WHEN 'lt' THEN CASE WHEN jsonb_typeof(actual)='number' AND jsonb_typeof(expected)='number' THEN (actual#>>'{}')::numeric<(expected#>>'{}')::numeric ELSE false END
   WHEN 'lte' THEN CASE WHEN jsonb_typeof(actual)='number' AND jsonb_typeof(expected)='number' THEN (actual#>>'{}')::numeric<=(expected#>>'{}')::numeric ELSE false END
   ELSE false END;
  IF NOT coalesce(result,false) THEN RETURN false; END IF;
 END LOOP;
 RETURN true;
END $$;
