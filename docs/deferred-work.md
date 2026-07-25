# Deferred work and known limitations

Decisions to *not* build something, recorded so they are not rediscovered as bugs. Each entry says what
is deferred, why, and what would justify revisiting it.

## Snyk Test API cannot publish results

The API scan engines (`ApiOpenSourceScanner`, `ApiCodeScanner`) send `publish_report: false`
unconditionally, and publishing to the Snyk Web UI is left entirely to `snyk monitor` (CLI). This is not a
choice — the Test REST API does not currently publish:

- **SCA over an inline dep-graph:** `publish_report: true` is accepted, echoed back in the test's
  `config`, and then ignored. No project is created or updated — not with `target_name` matching an
  existing target, not with `monitor: true`, and not with `scm_context.repo_url` naming the repository.
- **SAST over an SCM resource:** `publish_report: true` errors the whole test with
  `failed to create project ... got [400] status`. Adding `target_name`/`target_reference` is rejected
  outright (*"target configuration is not possible for a git URL input"*); Snyk's internal flow is named
  `sast_scm_stateless`.

Verified across three credentials including an Org Collaborator service account — the same role that
creates projects via `snyk monitor` — so it is not a permissions gap. Raised with Snyk (support case
`00132230`). **Revisit when** Snyk confirms a supported path to update an existing SCM-imported project
from a Test API result; at that point `ApiOpenSourceScanner`/`ApiCodeScanner` can publish and the reliance
on `snyk monitor` for the Web UI link can be reconsidered.

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
