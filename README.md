# snyk-ghe

A self-hosted **GitHub App** that posts Snyk security results — PR status checks, vulnerability
summary comments, and automated dependency-fix PRs — under its **own bot identity** instead of a
human user's Personal Access Token.

> **Why this exists:** Snyk's native GitHub integration acts on behalf of the user who connected it,
> so every PR check and comment shows up as *that person*. On **GitHub Enterprise Cloud with Data
> Residency** (`ghe.com`) with Enterprise Managed Users, provisioning a dedicated machine account is
> slow or impractical. A GitHub App gives you a first-class `yourapp[bot]` identity without a
> Marketplace listing or a human account.

> **Disclaimer:** This is an independent, community project. It *uses* the Snyk CLI but is not
> affiliated with, endorsed by, or supported by Snyk. "Snyk" is a trademark of Snyk Limited.

## What it does

- **PR status checks** — runs `snyk test` on each pull request and publishes a Check Run that can gate merges.
- **Summary comments** — posts a severity breakdown and the top findings as a PR comment from the bot.
- **Automated fix PRs** — for NuGet, patches the vulnerable `PackageReference` / `PackageVersion` /
  `packages.config` entries and opens a bot-authored PR targeting the contributor's branch.
- **Multi-org** — one App serves every org that installs it. Installations are discovered via
  webhooks; each org maps to a Snyk org in a registry.

## Architecture

```
GitHub webhook ──▶ HTTP front door ──▶ webhook queue ──▶ worker ──▶ event processor
                   (CA controller or    (Service Bus, or             │
                    Azure Function)       in-proc channel locally)    │
                          OrgPolicyResolver ◀── registry ◀────────────┤  (per-org Snyk mapping + policy)
                                                                      ▼
                                          clone ▶ snyk test ▶ Check Run + comment ▶ fix PR
```

The front door validates the `X-Hub-Signature-256` HMAC and enqueues the raw delivery, so GitHub is
acknowledged well within its ~10s timeout; the worker runs the (slow) scan off the queue.

- **.NET 10**, ASP.NET Core **controllers** (not minimal APIs).
- The installation registry is pluggable: **Azure Table Storage** or **AWS DynamoDB**, selected by
  `Storage:Provider`. The same binary runs on either cloud.

## Prerequisites

- A **GitHub App** registered on your enterprise (`ghe.com`), pointed at this service's webhook URL
  with the permissions and event subscriptions described in [GitHub App setup](#github-app-setup).
- A **Snyk** API token or OAuth client-credentials service account, and the Snyk org IDs you map to.
- A host that GitHub can reach over HTTPS (Azure Container Apps or AWS App Runner — both templated).

## GitHub App setup

Register the App under your enterprise's developer settings
(**Settings → Developer settings → GitHub Apps → New GitHub App**), then configure the following. The
App ID and a generated private key (`.pem`) from this page become `GitHub:AppId` and
`GitHub:PrivateKeyPem` (inline) or `GitHub:PrivateKeyPath` (file).

### Webhook

| Setting | Value |
| --- | --- |
| Webhook URL | `https://<your-host>/api/github/webhooks` (the deploy templates emit this as their `webhookUrl` / `WebhookUrl` output) |
| Content type | `application/json` |
| Secret | A random string; set the identical value as `GitHub:WebhookSecret` so deliveries pass `X-Hub-Signature-256` validation |
| SSL verification | Enabled |

### Repository permissions

| Permission | Access | Why |
| --- | --- | --- |
| **Metadata** | Read-only | Mandatory baseline for every GitHub App (selected automatically) |
| **Checks** | Read and write | Publish the PR status Check Run that can gate merges |
| **Contents** | Read and write | Clone the repository to scan (read); create the fix branch and commit manifest changes (write) |
| **Pull requests** | Read and write | Post the summary comment and open automated fix PRs; also the minimum access required to subscribe to the *Pull request* event |

No organization or account permissions are required.

> If you run with `Snyk:OpenFixPullRequests=false` (status checks and comments only, no fix PRs),
> **Contents** can be reduced to **Read-only** — clone-to-scan only needs read access.

### Subscribe to events

- **Pull request** — triggers the scan on the `opened`, `synchronize`, and `reopened` actions.

The **installation** and **installation_repositories** events — used to maintain the
org→installation registry as the App is installed, suspended, or removed — are delivered to every
GitHub App automatically. There is no checkbox for them and you cannot unsubscribe, so no action is
needed beyond setting the webhook URL above.

## Configuration

All keys bind from `appsettings.json` / environment variables (double-underscore form, e.g.
`GitHub__AppId`). Secrets should come from Key Vault / Secrets Manager, not config files.

| Key | Purpose |
| --- | --- |
| `GitHub:ApiBaseUrl` | REST base, e.g. `https://api.SUBDOMAIN.ghe.com/` (note: not the GHES `/api/v3` form) |
| `GitHub:AppId` / `GitHub:PrivateKeyPem` | App identity used to mint installation tokens |
| `GitHub:WebhookSecret` | Validates `X-Hub-Signature-256` on every delivery |
| `Snyk:Token` *or* `Snyk:OAuthClientId`/`Secret` | Snyk CLI authentication |
| `Snyk:DefaultSnykOrgId` / `DefaultSeverityThreshold` / `DefaultEcosystem` | Fallback policy for unmapped orgs |
| `Storage:Provider` | `AzureTable` or `DynamoDb` |
| `Storage:AdminApiKey` | Guards the `PUT /api/admin/orgs/{org}` mapping endpoint (closed if unset) |

Map a GitHub org to a Snyk org at runtime:

```bash
curl -X PUT https://<host>/api/admin/orgs/my-github-org \
  -H "X-Admin-Key: <admin-key>" -H "Content-Type: application/json" \
  -d '{"snykOrgId":"<snyk-org-uuid>","severityThreshold":"high","ecosystem":"nuget"}'
```

### One app, one enterprise

This service is built for **a single GitHub App registered on a single GitHub host**. A GitHub App
is registered against exactly one host (your `ghe.com` enterprise, or one GHES server), and all of
its installations live on that host. One deployment therefore serves **many orgs but exactly one
host**.

That is why `GitHub:ApiBaseUrl`, `GitHub:AppId`, and the private key are **static required settings**
rather than something discovered at runtime:

- **`AppId` + private key** identify the one app registration — constant regardless of how many orgs install it.
- **`ApiBaseUrl`** is invariant for a deployment: the app cannot span two hosts, so the REST base
  (`https://api.SUBDOMAIN.ghe.com/`) never changes. Webhook payloads *do* carry fully-qualified API
  URLs, so the host is technically derivable — but it would be a constant either way, and the app also
  makes calls outside of any webhook (e.g. an installation token exchange), which need the base
  configured up front.

To run this against a **different** enterprise/host, register a separate GitHub App there and deploy a
separate instance with its own `ApiBaseUrl`, `AppId`, and key. Pointing one deployment at multiple
GitHub hosts is out of scope — that would require a distributable app that discovers each operator's
host per installation.

## Deploy

- **Azure:** two topologies, both Container Apps + Service Bus + Table Storage + Key Vault —
  `.azure/main.bicep` (always-on) or `.azure/main-functions.bicep` (Azure Function front door, processing
  scales to zero). See `.azure/README.md`.
- **AWS:** `.aws/main.yaml` (App Runner + DynamoDB + Secrets Manager). See `.aws/README.md`.

## Build & test

```bash
dotnet build      # also runs the enforced code-style rules
dotnet test
```

See [CLAUDE.md](CLAUDE.md) for coding conventions.

## License

[MIT](LICENSE)
