namespace SnykGhe.Core.GitHub.Manifest
{
    /// <summary>
    /// Single source of truth for the GitHub App's required repository permissions and webhook event
    /// subscriptions. The manifest builder renders these into the App-creation manifest, and the
    /// README's "GitHub App setup" table mirrors the same set — keep them in sync.
    /// </summary>
    public static class GitHubAppDefinition
    {
        /// <summary>
        /// Repository permission name to access level, per the GitHub App manifest schema. Access is
        /// "read" or "write". installation token minting also requires "metadata: read" (mandatory).
        /// </summary>
        public static readonly IReadOnlyDictionary<string, string> Permissions = new Dictionary<string, string>
        {
            ["metadata"] = "read",       // mandatory baseline
            ["checks"] = "write",        // publish the PR Check Run
            ["contents"] = "write",      // clone to scan (read) + fix branch/commit (write)
            ["pull_requests"] = "write", // summary comment + open fix PRs
        };

        /// <summary>
        /// Webhook events the App subscribes to. The installation / installation_repositories events are
        /// delivered to every GitHub App automatically and cannot be listed here.
        /// <list type="bullet">
        /// <item><c>pull_request</c> — scan on opened / synchronize / reopened / ready_for_review; draft PRs are skipped.</item>
        /// <item><c>check_run</c> — re-scan when a user clicks "Re-run" on the Snyk check (rerequested).</item>
        /// <item><c>delete</c> — remove the Snyk branch reference when its branch is deleted (e.g. after a PR merges).</item>
        /// </list>
        /// </summary>
        public static readonly IReadOnlyList<string> Events = new[] { "pull_request", "check_run", "delete" };
    }
}
