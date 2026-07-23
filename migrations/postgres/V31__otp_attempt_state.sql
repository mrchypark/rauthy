CREATE TABLE otp_attempt_state
(
    scope_key varchar NOT NULL PRIMARY KEY,
    attempts  bigint  NOT NULL,
    expires   bigint  NOT NULL
);

CREATE INDEX idx_otp_attempt_state_expires ON otp_attempt_state (expires);
