## What and why

<!-- What problem does this solve, and why this approach? Rationale belongs here rather than in
     inline comments. Link the issue it closes. -->

## How it was tested

<!-- There is no CI. Say what you actually ran and what you observed. -->

- [ ] `dotnet build -warnaserror` passes
- [ ] `dotnet test` passes
- [ ] Tests added or updated for the behavior change

## Checklist

- [ ] Follows the [coding conventions](../CONTRIBUTING.md#coding-conventions) — no primary
      constructors, `_camelCase` private fields, bracketed namespaces
- [ ] No secrets, tokens, keys, enterprise hostnames, or organization names in the diff — including
      inside any screenshots
- [ ] Docs updated if this changes configuration keys, HTTP endpoints, or GitHub App permissions
- [ ] If the GitHub App's permissions or events changed, `GitHubAppDefinition` and the README tables
      were updated together
