# Contributing

Thanks for your interest in this project. It's an independent, community-maintained GitHub App — bug
reports, docs fixes, and pull requests are all welcome.

This project is not affiliated with, endorsed by, or supported by Snyk. Please don't file issues here
that are really about the Snyk platform or the Snyk CLI itself; those belong with Snyk.

## Before you start

- **Bugs and features** — open an issue first for anything non-trivial, so we can agree on the
  approach before you spend time on it. Typo and docs fixes can go straight to a PR.
- **Security vulnerabilities** — do **not** open a public issue. See [SECURITY.md](SECURITY.md).
- **Conduct** — participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).

## Prerequisites

| Tool | Why |
| --- | --- |
| [.NET 10 SDK](https://dotnet.microsoft.com/download) | Builds and tests the solution |
| [Snyk CLI](https://docs.snyk.io/snyk-cli/install-or-update-the-snyk-cli) on `PATH` | The scanner shells out to it. Override the location with `Snyk:CliPath` |
| `git` on `PATH` | The scanner clones the repository under test |

Scanning a given ecosystem also needs that ecosystem's toolchain present. For NuGet — the only
ecosystem with a fix-PR manifest patcher today — the scanner runs `dotnet restore` before
`snyk test`.

## Build and test

```bash
dotnet build      # compiles and runs the enforced code-style rules
dotnet test       # runs the xUnit tests in tests/
```

**There is currently no CI.** Nothing runs these for you when you open a pull request, so please run
both locally first. Style violations surface as build *warnings* by default; to see them the way a
strict build would, promote them to errors:

```bash
dotnet build -warnaserror
```

## Running the service locally

```bash
dotnet run --project src/SnykGhe.Service
```

It listens on `http://localhost:5076` and `https://localhost:7045`.

With no `ServiceBus:FullyQualifiedNamespace` and no `Sqs:QueueUrl` configured, the service falls back
to an in-process channel queue. That is fine for local work but is **not durable** — deliveries are
lost on restart. Don't use it anywhere real.

To exercise webhooks end to end you need a GitHub App pointed at a tunnel to your machine, plus the
secrets below. See the [README](README.md#github-app-setup) for how to register the App, including
the manifest flow that generates it for you.

### Configuration and secrets

Configuration binds from `appsettings.json` or environment variables, where `:` becomes `__` (so
`GitHub:AppId` is `GitHub__AppId`). The full key table lives in the
[README](README.md#configuration).

Never commit secrets. `.gitignore` already covers `*.pem`, `appsettings.*.Local.json`, `.env`,
`local.settings.json`, `.azure/*.local.bicepparam`, and `*.local.md` — put local overrides in those
and they'll stay out of git. The values that matter: the GitHub App private key, the webhook secret,
the Snyk token or OAuth client secret, and the admin API key.

**Screenshots need the same care as secrets.** Crop or redact enterprise names, organization names,
usernames, and avatars before committing an image. Text scrubbing tools like `grep` cannot see into
a PNG, so a screenshot is the easiest way to leak an affiliation without noticing.

## Project layout

| Project | Purpose |
| --- | --- |
| `src/SnykGhe.Contracts` | Dependency-free shared contracts — webhook signature validation, queue message property names |
| `src/SnykGhe.Core` | The domain and processing library: scanner, PR and baseline pipelines, registry, fix PRs, secrets, messaging |
| `src/SnykGhe.Service` | ASP.NET Core web host — controllers, DI composition root, `Dockerfile` |
| `src/SnykGhe.Functions` | Azure Functions isolated worker; the webhook front door for the scale-to-zero topology |
| `tests/SnykGhe.Core.Tests` | xUnit tests for `SnykGhe.Core` |

Deployment templates live in `.azure/` (Bicep) and `.aws/` (CloudFormation); each has its own README.

## Coding conventions

These are enforced by `.editorconfig` plus `EnforceCodeStyleInBuild` in `Directory.Build.props`, so
most violations show up as build warnings.

1. **No primary constructors — anywhere.** Classes and structs declare an explicit constructor that
   assigns fields in the body. This applies to records too: declare them with explicit
   `{ get; init; }` properties (`required` where a value must be supplied) and construct them with
   object initializers, rather than the positional `record Foo(string Bar)` form.

   Roslyn cannot flag primary-constructor *usage*, so unlike the rules below this one is upheld by
   convention and by review, not by the compiler. Please follow it by hand.

2. **Private instance fields are `_`-prefixed and camelCased** — `_logger`, `_options`. Constants and
   `static readonly` fields stay PascalCase.

3. **Namespaces use brackets** (block-scoped), not file-scoped.

The app targets `net10.0` and uses ASP.NET Core **controllers**, not minimal APIs. Nullable reference
types and implicit usings are on.

### Comments

Write comments for a future maintainer who wasn't part of the discussion that produced the change.
A comment should explain what the code does, or capture timeless technical rationale — an API quirk,
a security risk, a non-obvious constraint. Rationale for *why we picked this approach* belongs in the
pull request description or the commit message, not inline.

## Pull requests

1. Branch off `main`.
2. Keep the change focused. Unrelated cleanups in the same PR make review harder.
3. Add or update tests in `tests/SnykGhe.Core.Tests` for behavior changes.
4. Run `dotnet build -warnaserror` and `dotnet test` before pushing.
5. Update the README or the relevant `.azure/` / `.aws/` README when you change configuration keys,
   endpoints, or required GitHub App permissions. These are documented in tables that drift easily.
6. Write a PR description that explains the problem and why you solved it this way.

If you change the GitHub App's permission or event set, note that it's declared once in code, in
`GitHubAppDefinition` (`src/SnykGhe.Core/GitHub/Manifest/`), and mirrored by the tables in the
README. Both need to move together, or the manifest registration flow and the docs disagree.

## License

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE) that
covers this project.
