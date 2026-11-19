CREATE TABLE IF NOT EXISTS vps_expectations (
    vps_id INTEGER NOT NULL REFERENCES vps(id) ON DELETE CASCADE,
    template_id INTEGER NOT NULL REFERENCES service_templates(id) ON DELETE CASCADE,
    PRIMARY KEY (vps_id, template_id)
);
