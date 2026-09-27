-- A project-wide eligibility hint, independent of token consumption and link
-- retention. No clipboard contents or client identifiers are stored here.
CREATE TABLE project_clipboard_activity (
 project_id UUID PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
 last_eligible_at TIMESTAMPTZ NOT NULL
);
