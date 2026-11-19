-- +goose Up

CREATE EXTENSION IF NOT EXISTS timescaledb;

CREATE TABLE users (
    id            uuid PRIMARY KEY,
    username      text NOT NULL UNIQUE,
    password_hash text NOT NULL,
    role          text NOT NULL CHECK (role IN ('admin', 'user')),
    is_active     boolean NOT NULL DEFAULT false,
    created_at    timestamptz NOT NULL,
    activated_at  timestamptz,
    activated_by  uuid REFERENCES users (id),
    -- Reserved scope column (spec 17.5): unused in Phase 0, so authorization
    -- can be narrowed later without a migration against live data.
    scope_all     boolean NOT NULL DEFAULT true
);

CREATE TABLE sessions (
    token_hash bytea PRIMARY KEY,
    user_id    uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL
);

CREATE TABLE servers (
    id                uuid PRIMARY KEY,
    name              text NOT NULL UNIQUE,
    note              text NOT NULL DEFAULT '',
    created_at        timestamptz NOT NULL,
    decommissioned_at timestamptz
);

CREATE TABLE user_server_scopes (
    user_id   uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    server_id uuid NOT NULL REFERENCES servers (id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, server_id)
);

CREATE TABLE enrolment_tokens (
    token_hash  bytea PRIMARY KEY,
    server_id   uuid NOT NULL REFERENCES servers (id) ON DELETE CASCADE,
    expires_at  timestamptz NOT NULL,
    consumed_at timestamptz
);

CREATE TABLE agents (
    server_id        uuid PRIMARY KEY REFERENCES servers (id) ON DELETE CASCADE,
    hostname         text NOT NULL,
    agent_version    text NOT NULL,
    cert_fingerprint text NOT NULL,
    cert_not_after   timestamptz NOT NULL,
    enrol_key_hash   bytea NOT NULL,
    boot_id          text NOT NULL DEFAULT '',
    last_seen_at     timestamptz,
    revoked_at       timestamptz
);

CREATE TABLE audit_log (
    at     timestamptz NOT NULL,
    actor  text NOT NULL,
    action text NOT NULL,
    target text NOT NULL,
    detail jsonb NOT NULL DEFAULT '{}'
);

SELECT create_hypertable('audit_log', 'at');

-- +goose Down

DROP TABLE audit_log;
DROP TABLE agents;
DROP TABLE enrolment_tokens;
DROP TABLE user_server_scopes;
DROP TABLE servers;
DROP TABLE sessions;
DROP TABLE users;
