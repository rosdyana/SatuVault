-- SatuVault schema (MySQL 8.0+). Every human-readable value is an AES-256-GCM blob
-- (*_enc columns) encrypted by the application; *_idx columns are HMAC blind indexes.
-- Plaintext here: ids, foreign keys, timestamps, enums and counters only.

CREATE TABLE settings (
    name  VARCHAR(64)  NOT NULL PRIMARY KEY,
    value VARBINARY(1024) NOT NULL
) ENGINE=InnoDB;

CREATE TABLE users (
    id                CHAR(36)     CHARACTER SET ascii NOT NULL PRIMARY KEY,
    oid_idx           BINARY(32)   NOT NULL,
    email_idx         BINARY(32)   NOT NULL,
    email_enc         VARBINARY(1024) NOT NULL,
    name_enc          VARBINARY(1024) NOT NULL,
    totp_secret_enc   VARBINARY(256),
    totp_enrolled_at  DATETIME(6),
    totp_last_step    BIGINT       NOT NULL DEFAULT 0,
    totp_failures     INT          NOT NULL DEFAULT 0,
    totp_locked_until DATETIME(6),
    is_admin          BOOLEAN      NOT NULL DEFAULT FALSE,
    disabled          BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at        DATETIME(6)  NOT NULL,
    last_login_at     DATETIME(6),
    UNIQUE KEY users_oid (oid_idx),
    KEY users_email (email_idx)
) ENGINE=InnoDB;

CREATE TABLE teams (
    id         CHAR(36)     CHARACTER SET ascii NOT NULL PRIMARY KEY,
    name_enc   VARBINARY(1024) NOT NULL,
    created_at DATETIME(6)  NOT NULL,
    created_by CHAR(36)     CHARACTER SET ascii NOT NULL,
    deleted_at DATETIME(6)
) ENGINE=InnoDB;

CREATE TABLE team_members (
    team_id  CHAR(36) CHARACTER SET ascii NOT NULL,
    user_id  CHAR(36) CHARACTER SET ascii NOT NULL,
    role     ENUM('manager', 'member') NOT NULL,
    added_at DATETIME(6) NOT NULL,
    added_by CHAR(36) CHARACTER SET ascii NOT NULL,
    PRIMARY KEY (team_id, user_id),
    KEY team_members_user (user_id),
    CONSTRAINT fk_tm_team FOREIGN KEY (team_id) REFERENCES teams (id),
    CONSTRAINT fk_tm_user FOREIGN KEY (user_id) REFERENCES users (id)
) ENGINE=InnoDB;

CREATE TABLE servers (
    id         CHAR(36) CHARACTER SET ascii NOT NULL PRIMARY KEY,
    team_id    CHAR(36) CHARACTER SET ascii NOT NULL,
    data_enc   BLOB NOT NULL,
    version    INT NOT NULL DEFAULT 1,
    created_at DATETIME(6) NOT NULL,
    created_by CHAR(36) CHARACTER SET ascii NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    updated_by CHAR(36) CHARACTER SET ascii NOT NULL,
    deleted_at DATETIME(6),
    KEY servers_team (team_id),
    CONSTRAINT fk_servers_team FOREIGN KEY (team_id) REFERENCES teams (id)
) ENGINE=InnoDB;

CREATE TABLE items (
    id         CHAR(36) CHARACTER SET ascii NOT NULL PRIMARY KEY,
    team_id    CHAR(36) CHARACTER SET ascii NOT NULL,
    kind       ENUM('credential', 'secret') NOT NULL,
    server_id  CHAR(36) CHARACTER SET ascii,
    meta_enc   BLOB NOT NULL,
    secret_enc MEDIUMBLOB NOT NULL,
    version    INT NOT NULL DEFAULT 1,
    created_at DATETIME(6) NOT NULL,
    created_by CHAR(36) CHARACTER SET ascii NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    updated_by CHAR(36) CHARACTER SET ascii NOT NULL,
    deleted_at DATETIME(6),
    KEY items_team (team_id),
    KEY items_server (server_id),
    CONSTRAINT fk_items_team FOREIGN KEY (team_id) REFERENCES teams (id),
    CONSTRAINT fk_items_server FOREIGN KEY (server_id) REFERENCES servers (id)
) ENGINE=InnoDB;

-- Previous versions of an item (encrypted exactly like items), written before every update.
CREATE TABLE item_versions (
    item_id    CHAR(36) CHARACTER SET ascii NOT NULL,
    version    INT NOT NULL,
    meta_enc   BLOB NOT NULL,
    secret_enc MEDIUMBLOB NOT NULL,
    changed_at DATETIME(6) NOT NULL,
    changed_by CHAR(36) CHARACTER SET ascii NOT NULL,
    PRIMARY KEY (item_id, version),
    CONSTRAINT fk_iv_item FOREIGN KEY (item_id) REFERENCES items (id)
) ENGINE=InnoDB;

-- Append-only, HMAC-chained. The app's DB user gets SELECT, INSERT here and nothing else.
CREATE TABLE audit_events (
    seq         BIGINT NOT NULL PRIMARY KEY,
    ts          DATETIME(6) NOT NULL,
    actor_id    CHAR(36) CHARACTER SET ascii,
    action      VARCHAR(64) CHARACTER SET ascii NOT NULL,
    target_type VARCHAR(32) CHARACTER SET ascii,
    target_id   CHAR(36) CHARACTER SET ascii,
    details_enc BLOB NOT NULL,
    mac         BINARY(32) NOT NULL,
    KEY audit_ts (ts),
    KEY audit_actor (actor_id, ts),
    KEY audit_target (target_type, target_id, ts),
    KEY audit_action (action, ts)
) ENGINE=InnoDB;

-- Single row holding the chain head; locked FOR UPDATE by every audit write.
CREATE TABLE audit_head (
    id  TINYINT NOT NULL PRIMARY KEY,
    seq BIGINT NOT NULL,
    mac BINARY(32) NOT NULL
) ENGINE=InnoDB;

INSERT INTO audit_head (id, seq, mac) VALUES (1, 0, UNHEX(REPEAT('00', 32)));
