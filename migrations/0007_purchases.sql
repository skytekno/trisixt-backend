-- Only purchases verified through store server APIs reach this ledger.
-- Integer nanounits preserve Google Money precision and Apple milliunits.
CREATE TABLE verified_purchases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    visitor_id UUID NOT NULL,
    provider TEXT NOT NULL CHECK(provider IN ('apple','google')),
    application_id TEXT NOT NULL,
    environment TEXT NOT NULL CHECK(environment IN ('test','production')),
    transaction_id TEXT NOT NULL,
    product_id TEXT NOT NULL,
    purchase_kind TEXT NOT NULL CHECK(purchase_kind IN ('one_time','subscription')),
    currency TEXT NOT NULL CHECK(currency ~ '^[A-Z]{3}$'),
    amount_nanos BIGINT NOT NULL CHECK(amount_nanos>=0),
    quantity INTEGER NOT NULL CHECK(quantity>0),
    purchased_at TIMESTAMPTZ NOT NULL,
    verified_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(provider,application_id,environment,transaction_id),
    FOREIGN KEY(project_id,visitor_id) REFERENCES visitors(project_id,id)
);
CREATE INDEX verified_purchases_project_time ON verified_purchases(project_id,purchased_at DESC);
CREATE TRIGGER audit_verified_purchases AFTER INSERT ON verified_purchases FOR EACH ROW EXECUTE FUNCTION trisixt_audit_domain_change();
