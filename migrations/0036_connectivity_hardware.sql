CREATE TABLE android_hardware_models (model TEXT PRIMARY KEY,name TEXT NOT NULL);
CREATE TABLE hardware_refresh_state (
 singleton BOOLEAN PRIMARY KEY DEFAULT true CHECK(singleton),
 available_at TIMESTAMPTZ NOT NULL DEFAULT now(),updated_at TIMESTAMPTZ,
 last_error TEXT,attempts INTEGER NOT NULL DEFAULT 0
);
