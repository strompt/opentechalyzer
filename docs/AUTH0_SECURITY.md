# Opentechalyzer HTTP MCP — Auth0 security (review branch)

**Status:** proposal under review; **not deployed**. The current Coolify service is unchanged.

## Scope and why

The original `src/mcp.ts` accepted anonymous HTTP MCP requests. This branch
adds *resource-server* protection: Auth0 signs the bearer access tokens, while the
MCP server validates signature (RS256), issuer, audience, expiration, subject and
required scope **before** processing any MCP request.

Every GET, POST and DELETE on `/mcp` requires a token. OAuth protected-resource
metadata is public, and `/health` exposes only minimal health information.

A session is bound to the issuer+subject that initialized it; a second subject
cannot reuse its `Mcp-Session-Id`. Body requests are limited to 1 MiB. HTTP mode
fails to start when mandatory auth settings are missing.

## Configuration (Coolify, for a *future test deployment*)

Set the following **non-secret** environment variables on a separate staging app:

```dotenv
AUTH0_ISSUER=https://YOUR_TENANT.eu.auth0.com/
AUTH0_AUDIENCE=https://mcp.example.com/mcp
MCP_PUBLIC_URL=https://mcp.example.com/mcp
MCP_REQUIRED_SCOPE=scan:website
# Only if the MCP client uses browser-originated requests:
# MCP_ALLOWED_ORIGINS=https://chatgpt.com
```

`AUTH0_ISSUER` is the exact issuer in the Auth0 JWT, including trailing slash.
`AUTH0_AUDIENCE` must match an API identifier/audience explicitly configured
within Auth0. `MCP_PUBLIC_URL` must be the external HTTPS endpoint of **this**
service (ending in `/mcp`), and must match the protected resource metadata.

Create an Auth0 API with RS256 signing, RBAC and a `scan:website` permission,
then grant that permission to the intended test user/client. Do not put Auth0
management API tokens, signing keys, or Google credentials into GitHub.

Auth0's acceptance of MCP's OAuth `resource` parameter, ChatGPT client
registration (DCR/CIMD) and API audience selection requires a separate **real
authorization flow test**; serving resource metadata alone does not guarantee
interactive login will succeed.

## Smoke tests for a future staging environment

1. `GET /health` -> `200`, minimal public health information.
2. `GET /.well-known/oauth-protected-resource` -> `200` with Auth0 issuer.
3. `POST /mcp` with no bearer token -> `401` + `WWW-Authenticate`.
4. Malformed, expired, wrong-issuer or wrong-audience tokens -> `401`.
5. Valid token without required scope -> `403`.
6. Valid token with correct scope -> MCP initialize succeeds.
7. A second subject reusing another subject's session ID -> `403`.
8. Verify the origin policy matches how the chosen ChatGPT client connects.
9. Verify no alternate exposed port or domain bypasses auth at the edge.
10. Verify connection and reconnection using the actual ChatGPT OAuth flow.

## Deliberate limitations

- **No deploy, no Auth0 changes, no Coolify changes.**
- **No customer/tenant isolation yet**: principal binding alone does not provide
  multi-tenant authorization. Resource-level tenant checks, separate Google OAuth
  grants and storage segregation must be added before sale to clients.
- Existing tools still need a read/write permission audit; one scope currently
  gates all MCP tools. `import_external_database`, `track_tech_changes`, and
  BigQuery-backed `reverse_lookup` may have side effects or external costs.
- Further load testing and SSRF protection for user-controlled URLs are required.
- Current GitHub CI is the authoritative compile/test check; verify its outcome
  before considering this PR ready to merge.

## Migration sequence

1. Review and test this branch in CI.
2. Inspect Coolify ingress, current Auth0 tenant/API configuration and all routes.
3. Set up a **separate staging** endpoint and Auth0 test client/API.
4. Run unauthenticated rejection, JWT, cross-session and real ChatGPT flow tests.
5. Continue with data quality and multi-tenant audits.
6. Only after approval, plan an explicit production migration.
