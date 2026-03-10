-- Users table - stores our application users
CREATE TABLE users
(
    id         BIGSERIAL PRIMARY KEY,
    username   VARCHAR(50)  UNIQUE NOT NULL,
    password   VARCHAR(255)        NOT NULL,
    email      VARCHAR(100) UNIQUE NOT NULL,
    full_name  VARCHAR(100),
    enabled    BOOLEAN             DEFAULT true,
    created_at TIMESTAMP           DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP           DEFAULT CURRENT_TIMESTAMP
);

-- OAuth2 Clients table - stores registered applications
CREATE TABLE oauth_clients
(
    id                    BIGSERIAL PRIMARY KEY,
    client_id             VARCHAR(100) UNIQUE NOT NULL,
    client_secret         VARCHAR(255),
    client_name           VARCHAR(200)        NOT NULL,
    redirect_uris         TEXT[]              NOT NULL,
    grant_types           TEXT[]              NOT NULL,
    scopes                TEXT[]              NOT NULL,
    client_type           VARCHAR(20)         NOT NULL,
    access_token_validity INTEGER             DEFAULT 3600,
    refresh_token_validity INTEGER            DEFAULT 2592000,
    created_at            TIMESTAMP           DEFAULT CURRENT_TIMESTAMP,
    updated_at            TIMESTAMP           DEFAULT CURRENT_TIMESTAMP
);

-- Temporary storage for authorization codes
CREATE TABLE authorization_codes
(
    id                    BIGSERIAL PRIMARY KEY,
    code                  VARCHAR(255) UNIQUE NOT NULL,
    user_id               BIGINT              NOT NULL REFERENCES users (id),
    client_id             BIGINT              NOT NULL REFERENCES oauth_clients (id),
    redirect_uri          VARCHAR(500),
    scopes                TEXT[],
    code_challenge        VARCHAR(255),
    code_challenge_method VARCHAR(10),
    expires_at            TIMESTAMP           NOT NULL,
    created_at            TIMESTAMP           DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_auth_codes_code ON authorization_codes (code);
CREATE INDEX idx_auth_codes_expires_at ON authorization_codes (expires_at);

-- Access tokens storage
CREATE TABLE access_tokens
(
    id          BIGSERIAL PRIMARY KEY,
    token_id    VARCHAR(255) UNIQUE NOT NULL,
    token_value TEXT                NOT NULL,
    user_id     BIGINT              NOT NULL REFERENCES users (id),
    client_id   BIGINT              NOT NULL REFERENCES oauth_clients (id),
    scopes      TEXT[],
    expires_at  TIMESTAMP           NOT NULL,
    revoked     BOOLEAN             DEFAULT false,
    created_at  TIMESTAMP           DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_access_tokens_token_id ON access_tokens (token_id);
CREATE INDEX idx_access_tokens_user_id ON access_tokens (user_id);
CREATE INDEX idx_access_tokens_expires_at ON access_tokens (expires_at);

-- Refresh tokens storage
CREATE TABLE refresh_tokens
(
    id              BIGSERIAL PRIMARY KEY,
    token_id        VARCHAR(255) UNIQUE NOT NULL,
    token_value     TEXT                NOT NULL,
    user_id         BIGINT              NOT NULL REFERENCES users (id),
    client_id       BIGINT              NOT NULL REFERENCES oauth_clients (id),
    access_token_id BIGINT REFERENCES access_tokens (id),
    expires_at      TIMESTAMP           NOT NULL,
    revoked         BOOLEAN             DEFAULT false,
    created_at      TIMESTAMP           DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_refresh_tokens_token_id ON refresh_tokens (token_id);
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens (user_id);
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens (expires_at);

-- User consents table - track what users have approved
CREATE TABLE user_consents
(
    id         BIGSERIAL PRIMARY KEY,
    user_id    BIGINT    NOT NULL REFERENCES users (id),
    client_id  BIGINT    NOT NULL REFERENCES oauth_clients (id),
    scopes     TEXT[]    NOT NULL,
    expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (user_id, client_id)
);