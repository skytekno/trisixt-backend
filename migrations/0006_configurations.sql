
CREATE TABLE project_configurations (
    project_id UUID PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
    ios JSONB NOT NULL DEFAULT '{}',
    android JSONB NOT NULL DEFAULT '{}',
    web JSONB NOT NULL DEFAULT '{}',
    desktop JSONB NOT NULL DEFAULT '{}',
    redirect JSONB NOT NULL DEFAULT '{}',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
