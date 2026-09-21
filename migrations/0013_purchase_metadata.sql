ALTER TABLE verified_purchases ADD COLUMN device_id UUID;
ALTER TABLE verified_purchases ADD COLUMN session_id TEXT CHECK(char_length(session_id)<=200);
ALTER TABLE verified_purchases ADD FOREIGN KEY(project_id,device_id) REFERENCES devices(project_id,id) ON DELETE SET NULL(device_id);
ALTER TABLE verified_purchases DROP CONSTRAINT verified_purchases_purchase_kind_check;
ALTER TABLE verified_purchases ADD CHECK(purchase_kind IN ('one_time','subscription','rental'));
-- Subscription reconciliation remains distinct from product/rental reconciliation.
ALTER TABLE purchase_reconciliation DROP CONSTRAINT purchase_reconciliation_purchase_kind_check;
ALTER TABLE purchase_reconciliation ADD CHECK(purchase_kind IN ('one_time','subscription','rental'));
-- Billing migration may predate the native event type gate. Remove historical
-- users whose only events never counted toward the Rails MAU contract.
DELETE FROM monthly_active_visitors m WHERE NOT EXISTS(
 SELECT 1 FROM events e JOIN projects p ON p.id=e.project_id
 WHERE p.instance_id=m.instance_id AND e.visitor_id=m.visitor_id
 AND date_trunc('month',e.occurred_at AT TIME ZONE 'UTC')::date=m.month
 AND e.event_type IN ('view','open','install','reinstall','time_spent','reactivation','app_open','user_referred')
);
