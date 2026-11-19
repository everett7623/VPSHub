ALTER TABLE alert_events ADD COLUMN target_kind TEXT NOT NULL DEFAULT 'vps';
UPDATE alert_events SET target_kind='website'
  WHERE kind='website_expiry'
     OR (kind='http_probe' AND message LIKE 'website %');
