CREATE TABLE app_store_metadata (
 platform TEXT NOT NULL CHECK(platform IN('ios','android')), identifier TEXT NOT NULL,
 metadata JSONB NOT NULL DEFAULT '{}', artwork BYTEA, content_type TEXT,
 ready BOOLEAN NOT NULL DEFAULT false, expires_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 available_at TIMESTAMPTZ NOT NULL DEFAULT now(), attempts INTEGER NOT NULL DEFAULT 0,
 last_error TEXT, updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 PRIMARY KEY(platform,identifier), CHECK(artwork IS NULL OR octet_length(artwork)<=5242880)
);
