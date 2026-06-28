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
GitHub App webhook ──▶ WebhooksController ──▶ scan queue ──▶ ScanWorker
                                                              │
                          OrgPolicyResolver ◀── registry ◀────┤  (per-org Snyk mapping + policy)
                                                              ▼
                                          clone ▶ snyk test ▶ Check Run + comment ▶ fix PR
```

- **.NET 10**, ASP.NET Core **controllers** (not minimal APIs).
- The installation registry is pluggable: **Azure Table Storage** or **AWS DynamoDB**, selected by
  `Storage:Provider`. The same binary runs on either cloud.

## Prerequisites

- A **GitHub App** registered on your enterprise (`ghe.com`) with: webhook URL pointing at this
  service, a webhook secret, and permissions — *Checks: write*, *Contents: write*, *Pull requests:
  write*, *Metadata: read* — subscribed to the *Pull request* and *Installation* events.
- A **Snyk** API token or OAuth client-credentials service account, and the Snyk org IDs you map to.
- A host that GitHub can reach over HTTPS (Azure Container Apps or AWS App Runner — both templated).

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

- **Azure:** `infra/main.bicep` (Container Apps + Table Storage + Key Vault). See `infra/README.md`.
- **AWS:** `infra/aws/main.yaml` (App Runner + DynamoDB + Secrets Manager). See `infra/aws/README.md`.

## Build & test

```bash
dotnet build      # also runs the enforced code-style rules
dotnet test
```

See [CLAUDE.md](CLAUDE.md) for coding conventions.

## License

[MIT](LICENSE)
