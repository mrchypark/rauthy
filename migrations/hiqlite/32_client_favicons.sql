CREATE TABLE client_favicons
(
    client_id    TEXT NOT NULL
        CONSTRAINT client_favicons_client_id_fk
            REFERENCES clients
            ON UPDATE CASCADE ON DELETE CASCADE,
    res          TEXT NOT NULL,
    content_type TEXT NOT NULL,
    data         BLOB NOT NULL,
    updated      INTEGER DEFAULT 0 NOT NULL,
    CONSTRAINT client_favicons_pk
        PRIMARY KEY (client_id, res)
) STRICT;
