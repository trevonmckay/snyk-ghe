# Deferred work and known limitations

Decisions to *not* build something, recorded so they are not rediscovered as bugs. Each entry says what
is deferred, why, and what would justify revisiting it.

## Snyk Test API cannot update SCM-imported projects

The API scan engines (`ApiOpenSourceScanner`, `ApiCodeScanner`) send `publish_report: false`
unconditionally, and publishing to the Snyk Web UI is left entirely to `snyk monitor` (CLI). This is not a
choice — and it is not a bug. **Snyk Support confirmed (2026-07-27)** that `publish_report` on the Test API
routes the result to Snyk's project-publishing service, which only ever creates or updates a **CLI-origin
project**. It never writes back to a project imported through an SCM integration. So even where publishing
*succeeds*, it would spawn a separate CLI-origin project rather than update the existing GitHub Enterprise
projects — which is the opposite of the goal.

Per-path behaviour, all confirmed by Support:

- **SCA over an inline dep-graph:** `publish_report: true` is accepted, echoed back in the test's
  `config`, and then ignored — for inline resources the publish step is *not wired up to write anything
  yet*. No project is created or updated, under any variable tried (`target_name`, `monitor: true`,
  `scm_context.repo_url`).
- **SAST over an SCM resource:** `publish_report: true` errors the whole test. The test itself finishes;
  the failure is the publish step, which needs a project name to create its CLI-origin project and has
  none for a git-URL input, so it returns `failed to create project ... got [400] status`. Adding
  `target_name`/`target_reference` is rejected outright (*"target configuration is not possible for a git
  URL input"*) — those fields are unsupported for a git URL, not a workaround. Snyk's internal flow is
  named `sast_scm_stateless`.

Permissions were ruled out first (three credentials including an Org Collaborator service account, the
same role that creates projects via `snyk monitor`), then Support confirmed the cause is the feature's
current design, not authorization.

**Supported path today** for keeping the existing GitHub-Enterprise-imported projects fresh (per Support):
the SCM integration's own recurring tests / re-import, plus `snyk monitor` for Open Source (it refreshes
the snapshot on the existing npm project). That is exactly this app's architecture — API for testing with
`publish_report: false`, `snyk monitor` for the Web-UI publish.

**Revisit when** Snyk ships publishing to an existing SCM-origin project (Support is checking whether it is
on the roadmap, and re-verifying `publish_report` enrollment for our Org). At that point
`ApiOpenSourceScanner`/`ApiCodeScanner` can publish and the reliance on `snyk monitor` for the Web UI link
can be reconsidered. Support also agreed the accepted-then-ignored `publish_report` should be rejected at
request validation, and is passing that to the owning team.

## IaC has no Test API path

`Snyk:Engines:Iac=Api` is rejected at startup (`SnykServiceCollectionExtensions.ValidateEngines`). The API
exposes an `iac` scan configuration, but no resource type produces an IaC scan component, so every
submitted IaC test fails to assemble (`no scan components added to test plan`). IaC therefore always runs
on the CLI. **Revisit when** Snyk ships an IaC-capable resource type on the Test API.

## Snyk CLI version is unpinned

`src/SnykGhe.Service/Dockerfile` fetches `downloads.snyk.io/cli/stable/snyk-linux` at image-build time, so
each build gets the latest stable CLI. This is an accepted risk. The exposure worth knowing: the API Open
Source engine depends on the **undocumented** `snyk test --print-graph` flag (see `DepGraphGenerator`),
which is outside Snyk's compatibility guarantees — a future CLI could change or remove it and break
dep-graph generation with no build-time signal. **Revisit by** pinning to a known-good version
(`downloads.snyk.io/cli/vX.Y.Z/snyk-linux`) if reproducible builds or `--print-graph` stability become a
concern.

## Code Security summary row: no IaC link

`SnykProjectUrlResolver` builds the deep link for the Open Source and Code (SAST) summary rows but not for
IaC. Snyk IaC uses granular per-format project types rather than a single `iac` type, and those values
were never confirmed, so `SnykProjectType()` returns null for IaC and the row falls back to a plain count
(no regression). **Revisit by** confirming Snyk's IaC `types` value(s) and extending the resolver.

## Webhook processor: `PlanRescan()` extraction

`GitHubWebhookEventProcessor` handlers (`ProcessPullRequestWebhookAsync`, `ProcessCheckRunWebhookAsync`)
filter the action, null-check installation/repo, map fields, and delegate to the sealed
`PullRequestCheckService`. The scan-decision branches have no cheap unit test because the only seam is
mocking our own same-layer collaborator — a test smell, not a real boundary (an `IPullRequestCheckService`
interface was tried and reverted as gratuitous).

The agreed-but-deferred refactor extracts the decision + mapping into a pure static
`PlanRescan(...)` over primitives, returning `null` when no scan should run, so the branches unit-test with
plain values — no mocks, no interface. It does not cover the Octokit field extraction itself (that stays
in the handler, compiler-checked). Deferred because the glue is thin and the real risks (delivery,
signature, queue, scan execution) are integration concerns validated live. **Revisit when** the webhook
pipeline grows enough that the decision branches carry real logic worth isolating.
