-- People who sign in with OpenID Connect, the sign-ins in progress, and
-- their sessions (docs/DESIGN.md, "Console sign-in").
--
-- None of these tables belongs to a workspace: a person can be a member of
-- several. They are read and written by the server's own role before a
-- request's workspace is known, never by relink_tenant or relink_redirect,
-- which hold no privileges on them.

-- One row per identity at the provider. `member` is the name the person
-- has in workspace_members; it is chosen once, at first sign-in, so that it
-- matches no existing member, key owner or personal workspace.
CREATE TABLE users (
    id             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    issuer         text        NOT NULL CHECK (length(issuer) BETWEEN 1 AND 255),
    subject        text        NOT NULL CHECK (length(subject) BETWEEN 1 AND 255),
    member         text        NOT NULL UNIQUE CHECK (member ~ '^[a-z0-9][a-z0-9._-]{0,62}$'),
    email          text        CHECK (length(email) <= 320),
    display_name   text        CHECK (length(display_name) <= 200),
    created_at     timestamptz NOT NULL DEFAULT now(),
    last_login_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (issuer, subject)
);

-- A sign-in between the redirect to the provider and its return. Keyed by
-- the SHA-256 of the `state` parameter, which the browser also holds in a
-- cookie; taken (deleted) on return, so each one completes at most once.
CREATE TABLE oidc_logins (
    state_hash     bytea       PRIMARY KEY CHECK (length(state_hash) = 32),
    nonce          text        NOT NULL,
    code_verifier  text        NOT NULL CHECK (length(code_verifier) BETWEEN 43 AND 128),
    return_to      text        NOT NULL CHECK (length(return_to) <= 512),
    expires_at     timestamptz NOT NULL
);

CREATE INDEX oidc_logins_expires ON oidc_logins (expires_at);

-- Signed-in browsers. Only the SHA-256 of the session cookie is stored; the
-- CSRF token is returned by GET /v1/auth/session and must accompany every
-- state-changing request made with the cookie.
CREATE TABLE sessions (
    token_hash  bytea       PRIMARY KEY CHECK (length(token_hash) = 32),
    user_id     bigint      NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    csrf_token  text        NOT NULL CHECK (length(csrf_token) = 64),
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    CHECK (expires_at > created_at)
);

CREATE INDEX sessions_user ON sessions (user_id);
CREATE INDEX sessions_expires ON sessions (expires_at);
