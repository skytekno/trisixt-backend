ALTER TABLE link_clicks ADD COLUMN claimed_by UUID;
ALTER TABLE link_clicks ADD FOREIGN KEY(project_id,claimed_by) REFERENCES visitors(project_id,id) ON DELETE SET NULL(claimed_by);
