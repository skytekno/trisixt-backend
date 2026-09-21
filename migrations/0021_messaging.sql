CREATE TABLE notifications (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 title TEXT NOT NULL CHECK(char_length(title) BETWEEN 1 AND 250),
 subtitle TEXT NOT NULL DEFAULT '' CHECK(char_length(subtitle)<=1000),
 html TEXT NOT NULL DEFAULT '',
 auto_display BOOLEAN NOT NULL DEFAULT false,
 send_push BOOLEAN NOT NULL DEFAULT false,
 new_users BOOLEAN NOT NULL,
 existing_users BOOLEAN NOT NULL,
 platforms TEXT[] NOT NULL DEFAULT '{}',
 archived BOOLEAN NOT NULL DEFAULT false,
 scheduled_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 CHECK(new_users<>existing_users),
 CHECK(platforms <@ ARRAY['ios','android','web','windows','mac','linux','other']::text[]),
 UNIQUE(project_id,id)
);
CREATE INDEX notifications_delivery ON notifications(project_id,scheduled_at) WHERE NOT archived;
CREATE TABLE notification_messages (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 project_id UUID NOT NULL,
 visitor_id UUID NOT NULL,
 notification_id UUID NOT NULL,
 read BOOLEAN NOT NULL DEFAULT false,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 UNIQUE(notification_id,visitor_id),
 UNIQUE(project_id,id),
 FOREIGN KEY(project_id,notification_id) REFERENCES notifications(project_id,id) ON DELETE CASCADE,
 FOREIGN KEY(project_id,visitor_id) REFERENCES visitors(project_id,id) ON DELETE CASCADE
);
CREATE INDEX notification_messages_visitor ON notification_messages(project_id,visitor_id,created_at DESC);
CREATE TABLE push_outbox (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 project_id UUID NOT NULL,
 message_id UUID NOT NULL,
 device_id UUID NOT NULL,
 attempts INTEGER NOT NULL DEFAULT 0,
 available_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 lease_id UUID,
 lease_until TIMESTAMPTZ,
 sent_at TIMESTAMPTZ,
 invalidated_at TIMESTAMPTZ,
 last_error TEXT,
 UNIQUE(message_id,device_id),
 FOREIGN KEY(project_id,message_id) REFERENCES notification_messages(project_id,id) ON DELETE CASCADE,
 FOREIGN KEY(project_id,device_id) REFERENCES devices(project_id,id) ON DELETE CASCADE
);
CREATE INDEX push_outbox_pending ON push_outbox(available_at) WHERE sent_at IS NULL AND invalidated_at IS NULL;
CREATE TABLE project_push_profiles (
 project_id UUID PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
 android_profile TEXT,
 ios_profile TEXT,
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TRIGGER audit_notifications AFTER INSERT OR UPDATE OR DELETE ON notifications FOR EACH ROW EXECUTE FUNCTION trisixt_audit_domain_change();
CREATE TRIGGER audit_push_profiles AFTER INSERT OR UPDATE OR DELETE ON project_push_profiles FOR EACH ROW EXECUTE FUNCTION trisixt_audit_domain_change();
