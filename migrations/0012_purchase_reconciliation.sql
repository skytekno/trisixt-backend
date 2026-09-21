ALTER TABLE verified_purchases ADD COLUMN refund_updated_at TIMESTAMPTZ;
ALTER TABLE verified_purchases ADD COLUMN verification_source TEXT NOT NULL DEFAULT 'store_api' CHECK(verification_source IN ('store_api','sdk_reported'));
ALTER TABLE verified_purchases DROP CONSTRAINT verified_purchases_provider_check;
ALTER TABLE verified_purchases ADD CHECK(provider IN ('apple','google','reported'));
ALTER TABLE purchase_reconciliation ADD COLUMN purchase_kind TEXT NOT NULL DEFAULT 'subscription' CHECK(purchase_kind IN ('one_time','subscription'));
