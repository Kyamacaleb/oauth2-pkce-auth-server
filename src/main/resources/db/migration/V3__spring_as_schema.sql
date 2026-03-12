-- =============================================================================
-- V3: Simplify schema
--   • Drop custom token/code/consent tables (Spring AS manages its own store)
--   • Add Spring Authorization Server JPA-backed tables
-- =============================================================================

-- ─── 1. Drop unused custom tables ───────────────────────────────────────────
DROP TABLE IF EXISTS refresh_tokens       CASCADE;
DROP TABLE IF EXISTS access_tokens        CASCADE;
DROP TABLE IF EXISTS authorization_codes  CASCADE;
DROP TABLE IF EXISTS user_consents        CASCADE;

-- ─── 2. Spring Authorization Server — authorization store ───────────────────
--
-- This is the canonical schema for spring-authorization-server 1.x
-- using JdbcOAuth2AuthorizationService.
--
CREATE TABLE IF NOT EXISTS oauth2_authorization (
    id                            VARCHAR(100) NOT NULL,
    registered_client_id          VARCHAR(100) NOT NULL,
    principal_name                VARCHAR(200) NOT NULL,
    authorization_grant_type      VARCHAR(100) NOT NULL,
    authorized_scopes             VARCHAR(1000) DEFAULT NULL,
    attributes                    TEXT          DEFAULT NULL,
    state                         VARCHAR(500)  DEFAULT NULL,
    authorization_code_value      TEXT          DEFAULT NULL,
    authorization_code_issued_at  TIMESTAMP     DEFAULT NULL,
    authorization_code_expires_at TIMESTAMP     DEFAULT NULL,
    authorization_code_metadata   TEXT          DEFAULT NULL,
    access_token_value            TEXT          DEFAULT NULL,
    access_token_issued_at        TIMESTAMP     DEFAULT NULL,
    access_token_expires_at       TIMESTAMP     DEFAULT NULL,
    access_token_metadata         TEXT          DEFAULT NULL,
    access_token_type             VARCHAR(100)  DEFAULT NULL,
    access_token_scopes           VARCHAR(1000) DEFAULT NULL,
    oidc_id_token_value           TEXT          DEFAULT NULL,
    oidc_id_token_issued_at       TIMESTAMP     DEFAULT NULL,
    oidc_id_token_expires_at      TIMESTAMP     DEFAULT NULL,
    oidc_id_token_metadata        TEXT          DEFAULT NULL,
    refresh_token_value           TEXT          DEFAULT NULL,
    refresh_token_issued_at       TIMESTAMP     DEFAULT NULL,
    refresh_token_expires_at      TIMESTAMP     DEFAULT NULL,
    refresh_token_metadata        TEXT          DEFAULT NULL,
    user_code_value               TEXT          DEFAULT NULL,
    user_code_issued_at           TIMESTAMP     DEFAULT NULL,
    user_code_expires_at          TIMESTAMP     DEFAULT NULL,
    user_code_metadata            TEXT          DEFAULT NULL,
    device_code_value             TEXT          DEFAULT NULL,
    device_code_issued_at         TIMESTAMP     DEFAULT NULL,
    device_code_expires_at        TIMESTAMP     DEFAULT NULL,
    device_code_metadata          TEXT          DEFAULT NULL,
    CONSTRAINT pk_oauth2_authorization PRIMARY KEY (id)
    );

-- ─── 3. Spring Authorization Server — consent store ─────────────────────────
CREATE TABLE IF NOT EXISTS oauth2_authorization_consent (
    registered_client_id VARCHAR(100)  NOT NULL,
    principal_name        VARCHAR(200)  NOT NULL,
    authorities           VARCHAR(1000) NOT NULL,
    CONSTRAINT pk_oauth2_authorization_consent
    PRIMARY KEY (registered_client_id, principal_name)
    );

-- ─── 4. Spring Authorization Server — registered client store ───────────────
--
-- Used by JdbcRegisteredClientRepository.
-- The DataLoader seeds the client here via the repository API —
-- we only create the table structure, not the data.
--
CREATE TABLE IF NOT EXISTS oauth2_registered_client (
    id                            VARCHAR(100)  NOT NULL,
    client_id                     VARCHAR(100)  NOT NULL,
    client_id_issued_at           TIMESTAMP     DEFAULT CURRENT_TIMESTAMP NOT NULL,
    client_secret                 VARCHAR(200)  DEFAULT NULL,
    client_secret_expires_at      TIMESTAMP     DEFAULT NULL,
    client_name                   VARCHAR(200)  NOT NULL,
    client_authentication_methods VARCHAR(1000) NOT NULL,
    authorization_grant_types     VARCHAR(1000) NOT NULL,
    redirect_uris                 VARCHAR(1000) DEFAULT NULL,
    post_logout_redirect_uris     VARCHAR(1000) DEFAULT NULL,
    scopes                        VARCHAR(1000) NOT NULL,
    client_settings               VARCHAR(2000) NOT NULL,
    token_settings                VARCHAR(2000) NOT NULL,
    CONSTRAINT pk_oauth2_registered_client PRIMARY KEY (id)
    );