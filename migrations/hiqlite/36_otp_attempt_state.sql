CREATE TABLE otp_attempt_state
(
    scope_key TEXT NOT NULL PRIMARY KEY,
    attempts  INTEGER NOT NULL,
    expires   INTEGER NOT NULL
) STRICT;

CREATE INDEX idx_otp_attempt_state_expires ON otp_attempt_state (expires);
