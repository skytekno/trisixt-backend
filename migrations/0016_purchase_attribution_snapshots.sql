-- Historical referral attribution must survive mutable/deleted links. These
-- identifiers deliberately have no FK; project deletion still cascades the ledger.
ALTER TABLE verified_purchases ADD COLUMN attributed_link_id UUID;
ALTER TABLE verified_purchases ADD COLUMN inviter_id UUID;
ALTER TABLE purchase_ledger ADD COLUMN attributed_link_id UUID;
ALTER TABLE purchase_ledger ADD COLUMN inviter_id UUID;
CREATE FUNCTION trisixt_purchase_inviter(p_project UUID,p_link UUID) RETURNS UUID
LANGUAGE plpgsql STABLE AS $$
DECLARE candidate TEXT;
BEGIN
 SELECT metadata->>'visitor_id' INTO candidate FROM links
 WHERE project_id=p_project AND id=p_link AND metadata->>'sdk_generated'='true';
 RETURN nullif(candidate::uuid,'00000000-0000-0000-0000-000000000000'::uuid);
EXCEPTION WHEN invalid_text_representation THEN RETURN NULL;
END $$;
UPDATE verified_purchases SET attributed_link_id=link_id,inviter_id=trisixt_purchase_inviter(project_id,link_id) WHERE link_id IS NOT NULL;
UPDATE purchase_ledger l SET attributed_link_id=coalesce(p.attributed_link_id,l.link_id),inviter_id=coalesce(p.inviter_id,trisixt_purchase_inviter(l.project_id,l.link_id)) FROM verified_purchases p WHERE p.id=l.purchase_id;
CREATE FUNCTION trisixt_purchase_attribution_snapshot() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='UPDATE' AND OLD.attributed_link_id IS NOT NULL THEN
   NEW.attributed_link_id:=OLD.attributed_link_id;
   NEW.inviter_id:=OLD.inviter_id;
 ELSIF NEW.link_id IS NOT NULL THEN
   NEW.attributed_link_id:=NEW.link_id;
   NEW.inviter_id:=trisixt_purchase_inviter(NEW.project_id,NEW.link_id);
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER purchase_attribution_snapshot BEFORE INSERT OR UPDATE OF link_id ON verified_purchases
FOR EACH ROW EXECUTE FUNCTION trisixt_purchase_attribution_snapshot();
CREATE FUNCTION trisixt_ledger_attribution_snapshot() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='UPDATE' AND OLD.attributed_link_id IS NOT NULL THEN
   NEW.attributed_link_id:=OLD.attributed_link_id;
   NEW.inviter_id:=OLD.inviter_id;
 ELSE
   SELECT p.attributed_link_id,p.inviter_id INTO NEW.attributed_link_id,NEW.inviter_id
   FROM verified_purchases p WHERE p.id=NEW.purchase_id AND p.project_id=NEW.project_id;
   IF NEW.attributed_link_id IS NULL AND NEW.link_id IS NOT NULL THEN
     NEW.attributed_link_id:=NEW.link_id;
     NEW.inviter_id:=trisixt_purchase_inviter(NEW.project_id,NEW.link_id);
   END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER ledger_attribution_snapshot BEFORE INSERT OR UPDATE OF link_id ON purchase_ledger
FOR EACH ROW EXECUTE FUNCTION trisixt_ledger_attribution_snapshot();
CREATE INDEX purchase_ledger_referrals ON purchase_ledger(project_id,inviter_id,occurred_at) WHERE inviter_id IS NOT NULL;
