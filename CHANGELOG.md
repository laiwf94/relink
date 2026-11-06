# Changelog

Notable changes to relink, newest first. Each roadmap week is one entry; its
issue has the details of every task.

## Unreleased

### Week 1 (2026-11-02 to 2026-11-08): workspaces, roles, console sign-in, audit and quotas (#22)

Added:

- **Workspaces.** Every link, API key and statistic belongs to one workspace
  (migration 0003; existing rows moved into one personal workspace per
  owner). Postgres row-level security, keyed on a transaction-local
  `relink.workspace_id`, keeps tenants apart: a query run as `relink_tenant`
  without a workspace sees no rows. Every management query runs in a tenant
  transaction (`src/tenant.rs`), and redirects look links up through
  `relink_redirect`, a role that can only call the code lookup (migration
  0004).
- **Roles and scoped keys.** Members are owners, admins, editors or viewers.
  API keys carry the scopes `links:read`, `links:write` and `stats:read`,
  bounded by their owner's current role, plus an optional expiry. They are
  rotated with an overlap window (migration 0005). New commands:
  `create-key ... --workspace --scopes --expires-in` and
  `rotate-key ID --overlap`.
- **Console sign-in.** Sign-in works with any OpenID Connect provider:
  authorization code with PKCE, and RS256 or ES256 ID tokens checked with
  `ring`. Sessions are stored in Postgres, HttpOnly, with CSRF tokens
  (migration 0006). New routes: `/v1/auth/login`, `/v1/auth/callback`,
  `/v1/auth/session` and `/v1/auth/logout`.
- **Audit log.** One hash-chained, append-only chain per workspace
  (migration 0007). The chain is kept by a database trigger. It records link,
  key, workspace, user, session, plan and invitation changes with before and
  after states. `relink audit-verify [--workspace] [--anchors]` recomputes
  every hash.
- **Plans and quotas.** Plans limit links and monthly clicks (migration
  0008). Clicks are metered in the same transaction that writes the
  statistics. A workspace over a limit gets the stable error
  `quota_exceeded`; redirects are never refused. New: `GET /v1/usage` and
  the commands `plan-set`, `plan-assign` and `plan-list`.
- **Invitations.** Admins and owners invite people by email or member name
  with a role (migration 0009). Each invitation is a one-time link that only
  the person invited can accept, before it expires. Invitations can be
  revoked, every step is audited, and a workspace has at most 100 pending.
- **End to end.** `tests/workspaces.rs` walks the whole week through the
  real sign-in flow, the HTTP API and the binary. `examples/demo.sh` has a
  new step for scoped and rotated keys, workspace isolation, a plan limit and
  audit verification.

Changed:

- Links belong to their workspace rather than to the key owner who created
  them; `links.owner` still records the creator.
- The plan's domain limit moved to week 2 (#23), where domains are created.

Fixed:

- The limiter property test now allows the escrow undershoot the design
  permits across instances (#74).
