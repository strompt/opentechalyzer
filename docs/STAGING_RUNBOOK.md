# STRØM Intelligence MCP — staging handover

**Status:** Code-review branch, **not deployed**. Never deploy over the existing Opentechalyzer production service.

## Identity and environments

- GitHub repository owner: `strompt`. This is a **GitHub login**, not proof of the Auth0 email.
- Approved MCP test login: `strom.studio.pt@gmail.com` (must be email-verified by Auth0).
- Authentication: Auth0 as OAuth issuer and API resource server; STRØM MCP validates signed tokens.
- Google Sheets authorisation: **separate future Google OAuth integration**; no Sheets access in this PR.
- Target: separate Coolify **staging** service and hostname ending in `/mcp`.
- No implementation or Auth0 configuration was changed in production.

## What is implemented

- Resource metadata discovery at `/.well-known/oauth-protected-resource`.
- Fail-closed Auth0 token validation: RS256/JWKS, issuer, audience, expiry, scope, verified-email claim.
- Binds MCP sessions to authenticated issuer+subject (prevents a different subject reusing a session).
- HTTP staging hides potentially mutating/paid tools `track_tech_changes`,
  `reverse_lookup` and `import_external_database` by default.
- Minimal public `/health`, request size cap, optional browser origin allowlist.
- Read-only preflight: `node scripts/auth0-mcp-preflight.mjs https://STAGING_HOST/mcp`.

## Auth0 staging setup — manual and scoped

1. Identify the correct Auth0 tenant and review existing apps/APIs and custom domains. **Do not overwrite an existing client**.
2. Create a **separate Auth0 API (resource server)** for staging, signing RS256, with permission `scan:website`; decide its exact audience/API Identifier.
3. Prepare a staging OAuth client compatible with the actual ChatGPT MCP connector registration method. Validate support for the `resource` parameter, dynamic client registration/client metadata, PKCE, discovery and callback URLs in the **real** Auth0 tenant. Do not invent callback URLs: obtain them from the client registration flow.
4. Configure the Action from `docs/AUTH0_SECURITY.md` only against the staging API audience, emitting `https://stromstudio.pt/verified_email` solely for the **verified** allowed email.
5. Verify the staging app can request and receive access tokens for the correct API audience and scopes; a successful login without the expected token claims is **not** acceptance.
6. Review user registration policy, MFA and role permissions. Disable unneeded sign-up paths for the testing environment.

## Coolify staging setup — manual

1. Create a separate service/hostname from the security branch; leave production untouched.
2. Provide environment variables from `docs/AUTH0_SECURITY.md` (`AUTH0_ISSUER`, `AUTH0_AUDIENCE`, `MCP_PUBLIC_URL`, `MCP_REQUIRED_SCOPE`, `MCP_ALLOWED_EMAIL`).
3. Set `MCP_ALLOWED_EMAIL=strom.studio.pt@gmail.com` and **do not enable side-effect tools**.
4. Do not grant Google Cloud, BigQuery, Google Sheets or other private credentials to this container.
5. Publish only the HTTPS reverse-proxied `/mcp` endpoint; firewall unprotected raw ports and verify there are no alternate public routes.
6. Review egress rules to protect private IPs and internal services. **The current scanner does not yet implement full DNS-rebinding/redirect-safe SSRF protection.** For staging, isolate its outbound network and do not expose it to external customers.
7. Check memory, CPU, browser, concurrency and timeout caps before any scan against real public sites.

## Staging acceptance tests

- [ ] All CI checks green **for the commit being deployed**.
- [ ] `node scripts/auth0-mcp-preflight.mjs https://STAGING_HOST/mcp` passes.
- [ ] Anonymous MCP requests return `401` + OAuth Bearer metadata challenge.
- [ ] Malformed/expired/wrong-issuer/wrong-audience JWT returns `401`.
- [ ] Valid JWT missing `scan:website` returns `403`.
- [ ] Signed and approved verified-email claim allows the staging account.
- [ ] Different email, unverified email, missing claim or another user is rejected.
- [ ] An MCP session cannot be reused by a different Auth0 user.
- [ ] ChatGPT OAuth login and reconnection tested with the actual staging account.
- [ ] ChatGPT `tools/list` does **not** list the three side-effect tools in staging.
- [ ] Test of `detect_tech_stack` against one explicitly approved public website.
- [ ] Google Sheets and production services remain unchanged.
- [ ] Production rollback path confirmed; **do not merge or switch the production domain**.

## Known blockers before commercial release

- No full multi-tenant database, isolation or per-tool RBAC: current allowlist is for **one test account**.
- No separate per-customer Google OAuth / Google Sheets permission and write approval flow.
- URL/DNS/redirect SSRF protection and resource isolation are not yet production-grade.
- Real Auth0/ChatGPT dynamic OAuth client registration and `resource`-to-`audience` mapping not yet verified.
- External fingerprint dataset licensing and technology false-positive audits are separate review items (see PR #9).
- This PR is not a completed STRØM Intelligence MCP product; it hardens the existing Opentechalyzer server.

**Go/no-go:** deployment requires explicit approval, a staging hostname, confirmed Auth0 API settings and a security review. Nothing in this file authorises deployment.
