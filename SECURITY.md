# Security Policy

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues, pull requests, or
discussions.**

Report them privately through GitHub's [private vulnerability
reporting](https://github.com/trevonmckay/snyk-ghe/security/advisories/new): go to the repository's
**Security** tab and choose **Report a vulnerability**. This opens a draft advisory visible only to
you and the maintainers.

Please include, as far as you can:

- The type of issue and the component involved (webhook ingestion, admin endpoints, the registration
  flow, credential storage, the scanner, the fix-PR writer).
- The affected commit or tag, and the deployment topology if it's relevant (Azure Container Apps,
  Azure Functions front door, AWS App Runner, or local).
- Steps to reproduce, along with any proof-of-concept.
- What an attacker gains — this project's blast radius is unusually concrete (see below), so impact
  is worth spelling out.

You can expect an acknowledgement within **5 business days**. If a report is confirmed, a fix and a
GitHub Security Advisory will be published together, and you'll be credited unless you'd rather not
be.

## Supported versions

This project is pre-1.0 and there are no maintained release branches. Only the latest commit on
`main` receives security fixes. If you're running a deployment pinned to an older image tag, expect
to rebuild from `main` to pick up a fix.

## Scope

In scope: this repository — the service, the Azure Function front door, the deployment templates in
`.azure/` and `.aws/`, and the documentation where it describes an insecure configuration.

Out of scope, and better reported to their owners:

- The **Snyk** platform, the Snyk CLI, and the Snyk REST API. This is an independent project that
  *uses* the Snyk CLI; it is not affiliated with, endorsed by, or supported by Snyk.
- **GitHub**, GitHub Enterprise Cloud, and the GitHub REST API — report via
  [GitHub's own program](https://bounty.github.com/).
- Vulnerabilities in third-party NuGet dependencies. Report those upstream; open a normal issue here
  if this project needs to take the bump.

## Why this project is a sensitive target

A deployment of this app holds credentials that grant broad write access across every organization
that installs it:

- The **GitHub App private key**, which mints installation tokens for every installation.
- The **webhook secret**, which is the only thing authenticating inbound deliveries.
- A **Snyk service-account token or OAuth client secret**, typically scoped at the group level.
- The **admin API key**, which guards the org→Snyk-org mapping endpoint and the App registration
  flow.

With the App's repository permissions — Checks (write), Contents (write), and Pull requests (write) —
anyone holding those secrets can push branches, open pull requests, and publish check runs that gate
merges, across every installed organization.

Findings in these areas should be treated as high severity by default, and we'd particularly like to
hear about them:

- Bypassing `X-Hub-Signature-256` HMAC validation on the webhook endpoint, or any timing side channel
  in it.
- Bypassing or brute-forcing the admin API key on `/api/admin/*` or `/api/github/app/register`.
- Abuse of the App registration flow — forging the signed `state`, or replaying the one-time code —
  to redirect generated credentials.
- Leaking any of the above secrets into logs, check-run output, PR comments, or error responses.
- Command or argument injection into the `git clone` or `snyk` invocations by way of an
  attacker-controlled branch name, repository name, or manifest content.
- Path traversal in the fix-PR manifest patcher that writes outside the cloned working tree.

## Notes for operators

The admin and registration endpoints are protected only by a shared secret compared in constant time.
Treat that as defense in depth, not as your only control. Front them with your identity provider
(Entra ID / Easy Auth, or an equivalent) in any production deployment, and leave
`Storage:AdminApiKey` unset if you don't need those endpoints — they're closed when it's empty.

Store secrets in Key Vault or Secrets Manager, never in `appsettings.json`. In the Azure templates
the App private key and webhook secret are written at runtime by the registration flow and are never
seeded by the deployment, so a template redeploy cannot clobber or expose them.
