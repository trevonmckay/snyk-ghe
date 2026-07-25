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

- **PR status checks** — scans each pull request and publishes a Check Run per Snyk product that can gate
  merges: **`sca/snyk`** (open source, always on), plus optional **`sast/snyk`** (`snyk code test`) and
  **`iac/snyk`** (`snyk iac test`). A product the org isn't licensed for, or a repo with nothing to scan,
  skips its check rather than failing.
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

- **Pull request** — triggers the scan on the `opened`, `synchronize`, `reopened`, and `ready_for_review`
  actions. Draft PRs are not scanned; a PR opened as a draft is first scanned when it is marked ready for review.
- **Check run** — re-runs the scan when a user clicks **Re-run** on the Snyk check (the `rerequested`
  action). GitHub delivers this only to the App that owns the check run, so it always targets our own check.
- **Delete** — when a branch is deleted (typically the automatic deletion after a PR merges), removes the
  Snyk branch reference that the PR scan published, and the repository's Snyk target if that was its last
  reference. Tag deletions arrive on the same event and are ignored. Requires **Contents: Read**, already
  granted above. This cleanup calls the Snyk REST API with the OAuth service account, which therefore needs
  the **Remove Projects** (`org.project.delete`) permission — otherwise the deletes are rejected and logged.
- **Push** — when the **default branch** is pushed to (typically the commit a merged PR produces), runs a
  baseline scan and `snyk monitor`s the result under the default branch's target reference. This is the
  durable monitored snapshot Snyk alerts against as new vulnerabilities are disclosed — distinct from the
  ephemeral per-PR-branch monitoring. Pushes to other branches and tag pushes are ignored. Controlled by
  `Snyk:ScanDefaultBranch` (on by default); set it `false` to disable. Requires **Contents: Read**, already
  granted above.

The **installation** and **installation_repositories** events — used to maintain the
org→installation registry as the App is installed, suspended, or removed — are delivered to every
GitHub App automatically. There is no checkbox for them and you cannot unsubscribe, so no action is
needed beyond setting the webhook URL above.

### Automated registration (optional)

Instead of registering the App by hand, the service can generate it from a manifest so the permissions
and events above are pre-filled. The permission/event set is defined once in code
(`GitHubAppDefinition`) and mirrored by the table above.

1. **`GET /api/github/app/register`** (gated by the admin key — `X-Admin-Key` header or `?key=`; add
   `?org=<org>` to create it under an organization) renders a form that posts the manifest to your GitHub
   host. Click through GitHub's confirmation page.
2. GitHub redirects to **`GET /api/github/app/created`**, which exchanges the one-time code (valid one
   hour), writes the generated **private key** and **webhook secret** to the configured secret
   repository (`SecretRepository:Provider` = `AzureKeyVault` / `AwsSecretsManager`), and saves the
   (public, non-secret) **App ID** to the installation store (Table / DynamoDB) so the service loads it
   automatically — no manual `GitHub:AppId` step.
3. **Restart** the service so it loads the new secrets, then install the App on your orgs. (An explicit
   `GitHub:AppId` in config still wins if you prefer to set it.)

After install, GitHub redirects the installer to the App's **Setup URL**, served by
**`GET /api/github/setup`** — a confirmation page that shows the remaining step (mapping the org to a
Snyk org).

The deploy templates wire this up: the runtime identity is granted **write** to the secret store
(Azure: Key Vault Secrets Officer; AWS: `secretsmanager:PutSecretValue`) and `SecretRepository:*` is
preconfigured. These endpoints need public ingress, so the always-on Azure topology (`main.bicep`) and
AWS App Runner expose them directly. The scale-to-zero topology (`main-functions.bicep`) front-ends
*webhooks* with an Azure Function, but still gives the processing Container App its own external ingress
for the admin/registration routes — so registration works there too (call the `registrationUrl` output).
Because webhooks and registration then live on different hosts, that template sets `Registration:WebhookUrl`
to the Function's URL so the generated App's webhook points at the Function, not the Container App.

## Configuration

All keys bind from `appsettings.json` / environment variables (double-underscore form, e.g.
`GitHub__AppId`). Secrets should come from Key Vault / Secrets Manager, not config files.

| Key | Purpose |
| --- | --- |
| `GitHub:ApiBaseUrl` | REST base, e.g. `https://api.SUBDOMAIN.ghe.com/` (note: not the GHES `/api/v3` form) |
| `GitHub:AppId` / `GitHub:PrivateKeyPem` | App identity used to mint installation tokens |
| `GitHub:WebhookSecret` | Validates `X-Hub-Signature-256` on every delivery |
| `Snyk:Token` *or* `Snyk:OAuthClientId`/`Secret` | Snyk CLI authentication (static service-account token, or OAuth client-credentials — the service exchanges those for a short-lived token via `Snyk:OAuthTokenUrl`, default US `https://api.snyk.io/oauth2/token`; override for EU/AU) |
| `Snyk:DefaultSnykOrgId` / `DefaultSeverityThreshold` / `DefaultEcosystem` | Fallback policy for unmapped orgs |
| `Snyk:Monitor` | When `true`, also run `snyk monitor` after a PR's gating test so the Check Run's "View more details on Snyk" link points at the scan snapshot in the Snyk Web UI. Off by default — it creates a short-lived Snyk project per PR (the PR head branch is the target reference). Also drives `--report` publishing for the Code and IaC scans. Does not affect the default-branch baseline (`Snyk:ScanDefaultBranch`) |
| `Snyk:ScanDefaultBranch` | When `true` (default), a push to a repo's default branch runs a baseline scan and `snyk monitor`s it under the default-branch target reference — the durable snapshot Snyk alerts against as new vulnerabilities are disclosed. Set `false` to disable the push-triggered baseline |
| `Snyk:CoalesceBaselineScans` | When `true` (default), baseline scans are coordinated through the coordination table: a burst of pushes to one branch collapses to a single in-flight scan (latest commit wins), two workers never scan the same branch at once, and a commit already scanned (a Service Bus redelivery, or a push the in-flight scan's clone already picked up) is skipped. Set `false` to scan every push independently |
| `Snyk:ScanLeaseMinutes` | Lifetime of a baseline-scan single-flight lease (default `30`). Must exceed a scan's duration; also how long a crashed worker blocks that branch's baseline scans before the lease is reclaimed |
| `Snyk:ScanCode` / `Snyk:ScanIac` | When `true`, additionally run `snyk code test` (SAST) / `snyk iac test` and publish a separate `sast/snyk` / `iac/snyk` Check Run. Off by default (Snyk Code is separately licensed; IaC needs IaC files). A not-applicable product skips its check |
| `Snyk:Engines:OpenSource` / `Engines:Code` / `Engines:Iac` | Which engine runs each product: `Cli` (default) or `Api`. See [Scan engines](#scan-engines) — `Iac` accepts only `Cli`, and `Code=Api` requires `Snyk:ScmIntegrationId` |
| `Snyk:ScmIntegrationId` | Snyk SCM integration id (**Settings → Integrations → _your SCM_ → Integration ID**). Required when `Snyk:Engines:Code=Api`, which reads repository source through the integration rather than from the clone. Unused by the CLI engine |
| `Storage:Provider` | `AzureTable` or `DynamoDb` |
| `Storage:TableName` / `Storage:ScanCoordinationTableName` | Table/collection names for the installation registry (`installations`) and baseline-scan coordination (`scancoordination`). Both are created at startup |
| `Storage:AdminApiKey` | Guards the `PUT /api/admin/orgs/{org}` mapping endpoint and the registration flow (closed if unset) |
| `SecretRepository:Provider` | `AzureKeyVault` / `AwsSecretsManager` / `None` — where the registration flow writes generated secrets |
| `Registration:PublicBaseUrl` | This service's public URL used in the manifest (falls back to the request host) |
| `Registration:WebhookUrl` | Webhook URL placed in the manifest when the public webhook endpoint is a different host than this service (scale-to-zero topology: the Function). Falls back to `{PublicBaseUrl}/api/github/webhooks` |

### Scan engines

Each product runs either through the Snyk **CLI** (against the cloned working copy) or the Snyk
**Test REST API** (`src/Snyk.Client`). Selection is per product, so one product can be moved back to
the CLI without moving the others. Cutting over is a configuration change, not a code change.

| Product | `Cli` | `Api` |
| --- | --- | --- |
| `OpenSource` | `snyk test --all-projects` | Submits each project's dependency graph as an inline resource |
| `Code` | `snyk code test` | Submits an SCM resource; **requires `Snyk:ScmIntegrationId`** |
| `Iac` | `snyk iac test` | **Not available** — rejected at startup |

Three constraints come from Snyk's Test API, which is Early Access:

- **IaC has no API path.** The API exposes an `iac` scan configuration, but no resource type produces
  an IaC scan component, so every submitted IaC test fails to assemble. `Snyk:Engines:Iac=Api` is
  rejected at startup rather than failing each scan.
- **`Code=Api` scans through the SCM integration, not the clone.** The repository must already be
  imported into Snyk under that integration. A repository whose only Snyk target was created by
  `snyk monitor` does not qualify, and its check reports `Target not found` as a non-blocking neutral
  result naming the cause.
- **`OpenSource=Api` still needs the CLI**, which generates the dependency graphs the API scans. The
  API's other SCA inputs require the repository to be registered with Snyk beforehand.
- **The API scanners cannot publish results.** `publish_report: true` writes nothing. For an SCA inline
  dep-graph the test finishes normally and no project is created or updated — not with `monitor: true`,
  not with a `target_name` matching a natively-imported target, and not with `scm_context.repo_url`
  naming the repository. For SAST over an SCM resource it is worse: the test errors with
  `failed to create project ... got [400] status`, and supplying `target_name`/`target_reference` is
  rejected outright (*"target configuration is not possible for a git URL input"*).

  This is not a permissions problem. It reproduces identically under a read-only `org.read` token, a
  group-level service account, and an **Org Collaborator** service account — the same role the app's own
  Snyk service account uses to create projects via `snyk monitor`. The API scanners therefore send
  `publish_report: false`: publication that errors the test is worse than publication that never happens.

Monitoring (`snyk monitor`) always runs through the CLI, on either engine: it publishes a snapshot
rather than testing a revision, and it is currently the *only* way anything reaches the Snyk Web UI.
It covers Open Source, so `OpenSource=Api` keeps publishing exactly as before.

`Code=Api` does change what reaches the portal. The CLI Code scan publishes its own snapshot with
`snyk code test --report`; the API scan cannot, and `snyk monitor` does not publish SAST. Snyk Code
snapshots therefore stop being refreshed on that engine, and the Code check's deep link resolves only
if a project of that name already exists — for example one imported by the native SCM integration.

Map a GitHub org to a Snyk org at runtime:

```bash
curl -X PUT https://<host>/api/admin/orgs/my-github-org \
  -H "X-Admin-Key: <admin-key>" -H "Content-Type: application/json" \
  -d '{"snykOrgId":"<snyk-org-uuid>","severityThreshold":"high","ecosystem":"nuget"}'
```

Manually trigger a baseline scan (the same scan a push to the default branch runs). Scans the
default branch unless the request body overrides the branch; returns **202** once queued and runs in
the background, so results surface in the Snyk Web UI and logs rather than the HTTP response. Runs
regardless of `Snyk:ScanDefaultBranch` (that setting gates only the automatic push trigger):

```bash
# default branch (no body)
curl -X POST https://<host>/api/admin/scans/my-github-org/my-repo -H "X-Admin-Key: <admin-key>"

# a specific branch
curl -X POST https://<host>/api/admin/scans/my-github-org/my-repo \
  -H "X-Admin-Key: <admin-key>" -H "Content-Type: application/json" \
  -d '{"branch":"release/1.x"}'
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

Infrastructure-as-code templates for **Azure** and **AWS** ship with the repository, so you can stand
up a working deployment without assembling the resource graph yourself. Pick a cloud and a topology:

| Template | Cloud | Shape |
| --- | --- | --- |
| `.azure/main.bicep` | Azure | Always-on Container App (1–10 replicas), Service Bus, Table Storage, Key Vault, ACR |
| `.azure/main-functions.bicep` | Azure | Azure Function webhook front door; the processing Container App scales to zero (0–10 replicas) |
| `.aws/main.yaml` | AWS | App Runner, DynamoDB, SQS + dead-letter queue, Secrets Manager |

Each directory has its own README with the deploy commands, the RBAC each template grants, and how
secrets are handled — which differs by cloud. The Azure templates deliberately **do not** seed the
GitHub App private key or webhook secret; the [registration flow](#automated-registration-optional)
writes them at runtime, so a redeploy cannot clobber them. The AWS template takes both as `NoEcho`
CloudFormation parameters instead.

> **These are a starting point, not a production blueprint.** They're sized and shaped to get an
> adopter running quickly, and most environments will want to change them. In particular:
>
> - **The container image parameter defaults to a placeholder** (`mcr.microsoft.com/k8se/quickstart`).
>   Build and push this app's image to your own registry and pass it in, or the deployment comes up
>   serving the wrong thing.
> - **Ingress is public.** GitHub has to reach the webhook endpoint, but the admin and registration
>   routes are exposed on the same host, guarded only by a shared key. Front them with your identity
>   provider (Entra ID / Easy Auth, or equivalent), restrict ingress, or leave `Storage:AdminApiKey`
>   unset to close them entirely.
> - **Scaling, SKUs, and retention are guesses.** Replica bounds, the Service Bus and SQS tiers, queue
>   lock and visibility timeouts, and log retention are all set to reasonable defaults for a small
>   installation, not tuned to your traffic. A scan can run for minutes, so queue timeouts and
>   `Snyk:ScanLeaseMinutes` need to stay comfortably longer than your slowest repository.
> - **Networking, naming, and tagging follow no house convention.** Resource names derive from a
>   `baseName` parameter; there is no private networking, no custom domain, and no tag policy.
> - **No deployment pipeline is included.** `.github/workflows/` is empty — the templates are meant to
>   be run from your own CI or by hand.
>
> Treat them as a reference you fork and adapt, and review them against your organization's cloud
> policies before you run them.

## Build & test

```bash
dotnet build      # also runs the enforced code-style rules
dotnet test
```

There is no CI, so run both locally before opening a pull request.

## Contributing

Bug reports and pull requests are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for prerequisites,
the local run loop, and the enforced coding conventions. Participation is governed by the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Security

A deployment of this App holds a GitHub App private key, a webhook secret, a Snyk service-account
credential, and an admin API key — together enough to write to every organization that installs it.
Please report vulnerabilities privately through
[GitHub's private vulnerability reporting](https://github.com/trevonmckay/snyk-ghe/security/advisories/new),
never in a public issue. See [SECURITY.md](SECURITY.md) for scope and what we most want to hear about.

## License

[MIT](LICENSE)
