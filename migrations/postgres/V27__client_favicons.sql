CREATE TABLE client_favicons
(
    client_id    VARCHAR          NOT NULL
        CONSTRAINT client_favicons_client_id_fk
            REFERENCES clients
            ON UPDATE CASCADE ON DELETE CASCADE,
    res          VARCHAR          NOT NULL,
    content_type VARCHAR          NOT NULL,
    data         BYTEA            NOT NULL,
    updated      BIGINT DEFAULT 0 NOT NULL,
    CONSTRAINT client_favicons_pk
        PRIMARY KEY (client_id, res)
);
