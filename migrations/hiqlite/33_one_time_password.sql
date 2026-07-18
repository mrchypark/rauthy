CREATE TABLE one_time_password
(
    id          TEXT    NOT NULL
        CONSTRAINT one_time_password_pk
            PRIMARY KEY,
    user_id     TEXT    NOT NULL
        REFERENCES users
            ON UPDATE CASCADE ON DELETE CASCADE,
    name        TEXT    NULL,
    secret      BLOB    NOT NULL,
    enc_key_id  TEXT    NOT NULL,
    last_used   INTEGER NOT NULL,
    last_used_step INTEGER NOT NULL DEFAULT 0,
    kind        TEXT    NOT NULL CHECK (kind IN ('email', 'time')),
    is_active   INTEGER DEFAULT false NOT NULL
) STRICT;

CREATE UNIQUE INDEX one_time_password_user_kind_uindex
    ON one_time_password (user_id, kind);

CREATE INDEX one_time_password_user_active_kind_index
    ON one_time_password (user_id, is_active, kind);
