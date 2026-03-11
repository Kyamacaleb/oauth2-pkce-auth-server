-- If upgrading from V1: remove the username column
-- (skip this block if creating the DB fresh)
ALTER TABLE users DROP COLUMN IF EXISTS username;

-- Ensure email has the NOT NULL + UNIQUE constraints
ALTER TABLE users ALTER COLUMN email SET NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique ON users(email);
