-- A renewal transaction can be canceled once; repeated notifications and daily
-- reconciliation must not inflate cancellation analytics.
CREATE UNIQUE INDEX purchase_cancel_once ON purchase_ledger(purchase_id) WHERE event_type='CANCEL';
