# Project conventions

A self-hosted GitHub App that posts Snyk security results (PR checks, summary comments, and
automated fix PRs) under its own **bot identity** instead of a human user's PAT. Built for GitHub
Enterprise Cloud with Data Residency (`ghe.com`), where Enterprise Managed Users make a dedicated
service account impractical. One App instance serves many orgs; per-org Snyk mappings live in a
pluggable registry (Azure Table Storage or AWS DynamoDB).

## Layout

- `SnykGhe.slnx` at the root; application projects in `src/`, test projects in `tests/`.
- `.azure/` — Azure Bicep (`main.bicep`); `.aws/` — AWS CloudFormation (`main.yaml`).

## Coding conventions (enforced)

These are enforced via `.editorconfig` + `EnforceCodeStyleInBuild` (`Directory.Build.props`), so a
violation is a build warning. CI should build with `-warnaserror` to make them blocking.

1. **No primary constructors — anywhere.** Classes and structs use an explicit constructor that
   assigns fields in the body. **Records too:** declare records with explicit `{ get; init; }`
   properties (`required` where a value must be supplied) and construct them with object initializers
   — not the positional `record Foo(string Bar)` form. (Roslyn cannot flag primary-constructor
   *usage*, so this rule is convention-enforced, not analyzer-enforced — follow it by hand.)
2. **Private instance fields are prefixed with `_`** and camelCased (`_logger`, `_options`). Constants
   and `static readonly` fields stay PascalCase.
3. **Namespaces use brackets** (block-scoped), not file-scoped.

## Build & test

```bash
dotnet build      # compiles + runs the code-style rules
dotnet test       # runs the xUnit tests in tests/
```

## Notes for contributors

- The app targets `net10.0` and uses ASP.NET Core **controllers** (not minimal APIs).
- The GitHub REST base URL is configuration-driven (`GitHub:ApiBaseUrl`) — for `ghe.com` it is
  `https://api.SUBDOMAIN.ghe.com/`, which differs from the GHES `/api/v3` convention.
- Secrets (App private key, webhook secret, Snyk token, admin key) come from Key Vault / Secrets
  Manager and are never committed. `*.pem` and local override files are gitignored.
