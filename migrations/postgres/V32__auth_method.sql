ALTER TABLE sessions ADD COLUMN auth_method VARCHAR NOT NULL DEFAULT 'unknown';
ALTER TABLE refresh_tokens ADD COLUMN auth_method VARCHAR NOT NULL DEFAULT 'unknown';
ALTER TABLE refresh_tokens_devices ADD COLUMN auth_method VARCHAR NOT NULL DEFAULT 'unknown';
