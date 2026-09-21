ALTER TABLE verified_purchases ADD COLUMN platform TEXT NOT NULL DEFAULT 'other' CHECK(platform IN ('ios','android','web','desktop','other'));
UPDATE verified_purchases SET platform=CASE provider WHEN 'apple' THEN 'ios' WHEN 'google' THEN 'android' ELSE 'other' END;
