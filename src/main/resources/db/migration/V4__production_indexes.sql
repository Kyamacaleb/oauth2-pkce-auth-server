-- =============================================================================
-- This migration adds performance indexes and cleans up the old
-- =============================================================================

DROP TABLE IF EXISTS oauth_clients CASCADE;
CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);
CREATE INDEX IF NOT EXISTS idx_oauth2_auth_access_token
    ON oauth2_authorization (access_token_value);
CREATE INDEX IF NOT EXISTS idx_oauth2_auth_refresh_token
    ON oauth2_authorization (refresh_token_value);
CREATE INDEX IF NOT EXISTS idx_oauth2_auth_code
    ON oauth2_authorization (authorization_code_value);
CREATE INDEX IF NOT EXISTS idx_oauth2_auth_principal
    ON oauth2_authorization (principal_name);