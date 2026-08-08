# Admin API authentication

The admin/management API — per-org Snyk mappings, per-repo overrides, manual scans, and the
self-service registration entry point — is protected by one or more **configurable** authentication
methods:

| Method | How a caller proves identity | Best for |
| --- | --- | --- |
| `AdminKey` | A shared secret in the `X-Admin-Key` header | Bootstrap, break-glass, simple/single-operator setups, CI with a stored secret |
| `OAuth2` | An OIDC-issued **JWT bearer token** (`Authorization: Bearer …`) | Enterprise SSO: human operators and CI service principals authenticated by your IdP |

Which methods are accepted is driven entirely by `Auth:Methods`. Enable one or both; **any enabled
method satisfies a request**, so you can run both side by side during a migration. The webhook,
registration-callback, setup, and health endpoints are *not* covered by this — they authenticate
machine-to-machine (HMAC signature / one-time state token) and are unchanged.

> **This is a resource server.** The app only *validates* tokens; it never *acquires* them, so no
> provider SDK (e.g. MSAL) is involved. Any OIDC-compliant provider that publishes a discovery
> document and issues JWT access tokens works through the same standard `JwtBearer` path.

## Endpoints covered

Guarded by the `AdminAccess` policy:

- `GET|PUT|PATCH /api/admin/orgs/{org}` and `/api/admin/orgs/{org}/repos/{repo}` (and `DELETE` on the repo route)
- `POST /api/admin/scans/{org}/{repo}`
- `GET /api/github/app/register`

Not covered (machine-to-machine, unchanged): `POST /api/github/webhooks`,
`GET /api/github/app/created`, `GET /api/github/setup`, `GET /healthz`.

## Fail-fast configuration

`Auth` is validated at **startup**, but only genuine misconfigurations stop the app:

- `Auth:Methods` names an **unknown** method (a typo that would otherwise silently do nothing), or
- `OAuth2` is enabled but `Auth:OAuth2:Authority` or `Auth:OAuth2:Audience` is unset.

States that merely leave the admin API **closed** start normally:

- an **empty** `Auth:Methods` — a deployment configured entirely via app config need not use the admin
  endpoints; every admin request is then rejected with a clean `401`; and
- a blank `Auth:AdminKey:Secret` while `AdminKey` is enabled — that path is closed, no caller can
  authenticate with it.

Configure a method (with its settings) to open the admin API.

> **Upgrade note.** Earlier versions had no `Auth` section and left the admin endpoints closed when no
> admin key was set. That behavior is preserved: upgrading with a blank key (or no methods configured)
> still starts, with the admin API closed until you configure a method. The app refuses to start only on
> a typo'd method name or an `OAuth2` method missing its authority/audience.

## Configuration reference

| Key | Purpose |
| --- | --- |
| `Auth:Methods` | Array of enabled methods: any of `AdminKey`, `OAuth2` (case-insensitive). Empty leaves the admin API closed (the app still starts). |
| `Auth:AdminKey:Secret` | The shared secret for `AdminKey` (from Key Vault / Secrets Manager). If blank while `AdminKey` is enabled, that path is closed — no caller can authenticate with it — which is not a startup error. |
| `Auth:OAuth2:Authority` | OIDC issuer URL; `{Authority}/.well-known/openid-configuration` is read for signing keys + issuer. Required when `OAuth2` is enabled. |
| `Auth:OAuth2:Audience` | Expected token `aud`. The exact value your IdP puts there depends on the provider (and, for some, the token version) — see [Provider setup](#provider-setup). Required when `OAuth2` is enabled. |
| `Auth:OAuth2:RequireHttpsMetadata` | Require HTTPS for metadata (default `true`; set `false` only for a local dev IdP over HTTP). |
| `Auth:OAuth2:RequiredScopes` | Scopes that authorize a request — a token needs **any** one. Empty + empty roles ⇒ any validly-issued token passes. Matched exactly (case-sensitive). |
| `Auth:OAuth2:RequiredRoles` | Roles/groups that authorize a request — a token needs **any** one. Consumer-defined to match your IdP. |
| `Auth:OAuth2:ScopeClaimTypes` | JWT claim types inspected for scopes. Default `["scp", "scope"]`. A space-delimited value is split. |
| `Auth:OAuth2:RoleClaimTypes` | JWT claim types inspected for roles. Default `["roles", "role", "groups"]`. |

### Authorization: scope OR role

Beyond a valid token (correct issuer, audience, signature, expiry), you decide what distinguishes an
admin from any authenticated principal in your directory:

- Configure `RequiredScopes`, `RequiredRoles`, or both. A token is authorized if it carries **any**
  required scope **or** **any** required role.
- Leave **both empty** to accept **any** validly-issued token for the audience (least strict).
- The `AdminKey` credential is fully trusted and bypasses the scope/role gate entirely.

Inbound claim mapping is disabled, so claim types are the **raw JWT names** your IdP emits (e.g.
`scp`, `roles`, `groups`) — not the long WS-* URIs. Override `ScopeClaimTypes` / `RoleClaimTypes` if
your IdP uses a custom claim.

## Example configuration

`AdminKey` only (default):

```jsonc
"Auth": {
  "Methods": ["AdminKey"],
  "AdminKey": { "Secret": "<from your secret store>" }
}
```

`OAuth2` with a required scope, plus the admin key kept for break-glass:

```jsonc
"Auth": {
  "Methods": ["OAuth2", "AdminKey"],
  "OAuth2": {
    "Authority": "https://login.microsoftonline.com/<tenant-id>/v2.0",
    "Audience": "<api application (client) ID GUID>",
    "RequiredScopes": ["snykghe.admin"],
    "RequiredRoles": []
  }
}
```

## Provider setup

The app validates any OIDC-compliant JWT, so it is not tied to a particular identity provider. The
steps below differ only in where you register the API and how you model "admin"; the provider-specific
quirks (what lands in `aud`, how to obtain a token) live in each subsection. In every case,
`Authority` + `Audience` come from that registration, and you choose scope- or role/group-based
authorization.

### Microsoft Entra ID

1. **Register the API** (App registration) → *Expose an API*: set an Application ID URI, e.g.
   `api://snyk-ghe`. Clients request tokens against this URI (e.g. `<uri>/.default`); it is *not*
   necessarily the audience — see the next step.
2. **Set `Audience` to match the token version.** Setting a custom Application ID URI switches the API
   to **v2** access tokens (`requestedAccessTokenVersion: 2`), and Entra then puts the API's
   **application (client) ID GUID** in the `aud` claim — so `Audience` is that GUID, *not* the URI.
   Only v1 tokens (`requestedAccessTokenVersion` `null`/`1`) carry the Application ID URI in `aud`.
   When unsure, decode a real token at `jwt.ms` and copy its `aud` verbatim.
3. `Authority` = `https://login.microsoftonline.com/<tenant-id>/v2.0`.
4. Model admin either as:
   - a **delegated scope** (Expose an API → add a scope, e.g. `snykghe.admin`) → set
     `RequiredScopes: ["snykghe.admin"]` (scopes arrive in the `scp` claim); or
   - an **app role** (App roles → assign to users/groups/apps) → set `RequiredRoles: ["<role value>"]`
     (roles arrive in the `roles` claim). App roles carry in `roles` for both user and
     client-credentials tokens — but only if the role's **allowed member types** include the caller
     type (a `User`-only role is never present in an app-only/client-credentials token).

**Getting a token from a public client (e.g. the Azure CLI).** For a *delegated* token you must
**expose at least one delegated scope** under *Expose an API* — without one, Entra rejects the
request with `AADSTS650057: Invalid resource` (there is nothing for the client to ask for), even if
admin is modeled purely as an app role. This is the only hard requirement. Optionally, add the client
under *Expose an API → Authorized client applications* (the Azure CLI is
`04b07795-8ddb-461a-bbee-02f9e1bf7b46`) to pre-authorize it and skip the per-user consent prompt;
otherwise the user consents interactively on first use. The resulting token carries both the `scp`
(scope) and any assigned `roles`, so either can satisfy the [scope-OR-role gate](#authorization-scope-or-role):

```bash
az account get-access-token --resource <application-id-uri> --query accessToken -o tsv
```

### Okta

1. Create (or reuse) a **custom authorization server**; its issuer is your `Authority`, e.g.
   `https://<org>.okta.com/oauth2/<authz-server-id>`.
2. Define the API/resource **audience** on that authorization server → your `Audience`.
3. Add a **scope** (e.g. `snykghe.admin`) and/or emit a **groups** claim, then set `RequiredScopes`
   and/or `RequiredRoles` accordingly. Okta places scopes in `scp`; if you emit groups under a custom
   claim, add it to `RoleClaimTypes`.

### PingFederate / PingOne

1. Configure an **OAuth/OIDC** authorization server; its issuer is your `Authority`.
2. Define the **audience/resource** the tokens target → your `Audience`.
3. Grant a **scope** or a **group** claim and map it via `RequiredScopes` / `RequiredRoles`
   (add the group claim name to `RoleClaimTypes` if it isn't `groups`).

## Getting a token to call the API

The app doesn't issue tokens — obtain one from your IdP out of band.

> **Delegated (user/interactive) tokens need a scope exposed on the API.** However you model
> authorization, the OAuth2 delegated flow requires the API to expose at least one scope before a
> public or interactive client (a CLI, a desktop tool, a SPA) can request a token against it — an API
> that exposes none cannot issue a delegated token, even when admin is modeled purely as a role or
> group. This is a property of the flow, not of any one provider; where and how you expose a scope is
> provider-specific (see [Provider setup](#provider-setup)). Client-credentials (service-to-service)
> tokens are unaffected.

Human operator (Entra, via Azure CLI):

```bash
TOKEN=$(az account get-access-token --resource api://snyk-ghe --query accessToken -o tsv)
curl -X PATCH https://<host>/api/admin/orgs/my-github-org \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"severityThreshold":"critical"}'
```

CI / service-to-service (client-credentials, any IdP):

```bash
TOKEN=$(curl -s -X POST "$AUTHORITY/oauth2/v2.0/token" \
  -d grant_type=client_credentials \
  -d client_id="$CLIENT_ID" -d client_secret="$CLIENT_SECRET" \
  -d scope="api://snyk-ghe/.default" | jq -r .access_token)
curl -X POST https://<host>/api/admin/scans/my-github-org/my-repo \
  -H "Authorization: Bearer $TOKEN"
```

(The token endpoint and `scope`/`resource` parameters vary by provider; consult your IdP.)

## Registration flow and the admin key

`GET /api/github/app/register` renders a page in a **browser**, and browser navigation cannot send an
`Authorization` header — so this endpoint additionally accepts the admin key as `?key=<admin-key>`
(only this endpoint; the mutating endpoints never accept a query-string key, which would leak into
access logs). In practice this makes **`AdminKey` the bootstrap path** for registration.

The registration flow signs a one-time state token to tie the GitHub callback back to a gated
`/register` request. Its signing key is `Registration:StateSigningKey` when set, otherwise
`Auth:AdminKey:Secret`. To run registration under an **OAuth2-only** deployment, set
`Registration:StateSigningKey` explicitly (and reach `/register` with a bearer token, e.g. via a
proxy/tool that can inject the header). Admin-key deployments need no change.

## Notes and limitations

- **Google is not supported for the API path.** Google's OAuth2 access tokens are opaque, not JWTs,
  so they can't be validated by signature; only Google *ID tokens* are JWTs. Entra, Okta, and Ping
  issue JWT access tokens and are the supported providers. See
  [deferred work](deferred-work.md#google-and-interactive-login-ui-not-supported).
- **401 vs 403.** A missing/invalid credential is `401`. A valid token that lacks the required
  scope/role is `403`.
- **Multiple schemes.** With both methods enabled, a request is accepted if it satisfies either — a
  valid `X-Admin-Key` or a valid bearer token.
