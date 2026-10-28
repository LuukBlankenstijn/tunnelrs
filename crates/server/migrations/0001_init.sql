CREATE TABLE meta (
    id INTEGER PRIMARY KEY NOT NULL CHECK (id = 0),
    db_id TEXT NOT NULL
);

INSERT INTO meta (id, db_id) VALUES (0, lower(hex(randomblob(16))));

CREATE TABLE connectors (
    id TEXT PRIMARY KEY NOT NULL,
    enrollment TEXT NOT NULL CHECK (enrollment IN ('pending', 'approved', 'denied', 'revoked')),
    updated_at INTEGER NOT NULL
);

CREATE TABLE grants (
    connector_id TEXT PRIMARY KEY NOT NULL REFERENCES connectors (id),
    patterns TEXT NOT NULL,
    tls_modes TEXT
);

CREATE TABLE announcements (
    connector_id TEXT NOT NULL REFERENCES connectors (id),
    hostname TEXT NOT NULL,
    tls TEXT NOT NULL CHECK (tls IN ('terminate', 'passthrough')),
    meta TEXT NOT NULL,
    PRIMARY KEY (connector_id, hostname)
);

CREATE TABLE routes (
    hostname TEXT PRIMARY KEY NOT NULL,
    tls TEXT NOT NULL CHECK (tls IN ('terminate', 'passthrough')),
    meta TEXT NOT NULL,
    offline_since INTEGER
);
