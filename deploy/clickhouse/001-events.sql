CREATE DATABASE IF NOT EXISTS trisixt;
CREATE TABLE IF NOT EXISTS trisixt.events (
    id UUID,
    event_id UUID,
    project_id UUID,
    visitor_id UUID,
    event_type LowCardinality(String),
    occurred_at DateTime64(6, 'UTC'),
    properties String
)
ENGINE = ReplacingMergeTree()
PARTITION BY toYYYYMM(occurred_at)
ORDER BY (project_id, event_id);
