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
MCP_ALLOWED_EMAIL=strom.studio.pt@gmail.com
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

## Restricting the test account (email allowlist)

The only permitted email for staging is `strom.studio.pt@gmail.com`.
The GitHub repository login (`strompt`) is separate from the Auth0 identity.
Do not infer that the GitHub login's primary email matches an Auth0 user.

The MCP does not trust a raw email header or the usual JWT `email` claim.
The token MUST contain a cryptographically signed **verified email claim**
(`https://stromstudio.pt/verified_email`) emitted by Auth0 **only** when
`event.user.email_verified === true`.

Example Auth0 **Post-Login Action** (to configure in a **staging** Auth0
application; not executed by this branch). Use the **API audience**, rather
than a fixed OAuth `client_id`, because ChatGPT may connect using dynamically
registered OAuth clients (DCR or CIMD):

```js
exports.onExecutePostLogin = async (event, api) => {
  // Set STRM_MCP_API_AUDIENCE as an Auth0 Action secret. Its value must
  // equal the Auth0 API Identifier / AUTH0_AUDIENCE configured on the MCP.
  const audience = event.secrets?.STRM_MCP_API_AUDIENCE;
  if (!audience) return; // No claim issued; the MCP itself denies access.

  // The Action can be linked to a tenant with other applications/APIs.
  // A missing or different resource server is not this MCP.
  if (event.resource_server?.identifier !== audience) return;

  const allowedEmail = 'strom.studio.pt@gmail.com';
  const verifiedEmail = event.user.email_verified === true
    && typeof event.user.email === 'string'
    ? event.user.email.trim().toLowerCase()
    : '';
  if (verifiedEmail !== allowedEmail) {
    api.access.deny('Account not authorized for STRØM MCP staging.');
    return;
  }

  api.accessToken.setCustomClaim(
    'https://stromstudio.pt/verified_email',
    verifiedEmail,
  );
};
```

**Important:** In Auth0 Actions, `event.resource_server.identifier` identifies
the target API when that context is available. It may be absent if the OAuth
request has not been associated with the MCP API audience. The Action must
then avoid modifying other applications' logins and omit the claim; the MCP
will deny any token missing the signed verified-email claim.

Set `STRM_MCP_API_AUDIENCE` to the **actual Auth0 API Identifier**, not an
Auth0 client ID or GitHub login. Ensure the OAuth client can obtain an access
token for that audience; in particular, enable the relevant Auth0 MCP
resource-parameter compatibility mode if supported by your tenant, and
validate the actual ChatGPT login flow. A passing JWT unit test is not
proof that dynamic client registration or token audience mapping works.

The email allowlist is a **test-access policy**, not a commercial multi-tenant
authorization system. When onboarding paying customers, replace it with
per-tenant identity, user IDs, roles and permissions, not a single shared
email or global allowlist. Consider also binding initial staging access to
the exact immutable Auth0 `sub` once it has been confirmed in the tenant.

The Action and Auth0 client configuration have **not** been installed or
verified on any real Auth0 tenant. There has been no production deploy.

## Read-only staging preflight (no user tokens needed)

Once a separate staging service is deployed **after explicit approval**, run:

```bash
node scripts/auth0-mcp-preflight.mjs https://STAGING_HOST/mcp
```

The preflight checks HTTPS, OAuth protected-resource discovery, Auth0 issuer
discovery, anonymous MCP 401 and Bearer challenge headers. It intentionally
does not log in, request tokens, or modify remote services.

Successful preflight **does not prove** that ChatGPT can authenticate, that
user-identity claims are emitted, or that the real service has no unprotected
alternate port. These are separate manual checks.

## Smoke tests for a future staging environment

1. `GET /health` -> `200`, minimal public health information.
2. `GET /.well-known/oauth-protected-resource` -> `200` with Auth0 issuer.
3. `POST /mcp` with no bearer token -> `401` + `WWW-Authenticate`.
4. Malformed, expired, wrong-issuer or wrong-audience tokens -> `401`.
5. Valid token without required scope -> `403`.
6. Valid token with correct scope **and signed verified-email claim for the approved account** -> MCP initialize succeeds.
7. Wrong/missing signed verified-email claim -> `403`; a second subject reusing another subject's session ID -> `403`.
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
