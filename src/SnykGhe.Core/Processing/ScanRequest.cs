namespace SnykGhe.Core.Processing
{
    /// <summary>A unit of work: scan one pull request head and report results back to GitHub.</summary>
    public sealed record ScanRequest
    {
        public required long InstallationId { get; init; }

        public required string Owner { get; init; }

        public required string Repo { get; init; }

        public required string CloneUrl { get; init; }

        public required int PrNumber { get; init; }

        public required string HeadRef { get; init; }

        public required string HeadSha { get; init; }

        /// <summary>
        /// The pull request's base (target) branch — the branch it merges into (e.g. <c>main</c> for a
        /// <c>feature → main</c> PR). Drives the optional base-branch scan filter. Null when the base branch
        /// could not be determined, in which case the filter fails open (the PR is scanned).
        /// </summary>
        public string? BaseRef { get; init; }

        /// <summary>The repository's default branch, used to resolve the <c>$default</c> scan-filter token. May be null.</summary>
        public string? DefaultBranch { get; init; }

        /// <summary>
        /// The clone URL with any trailing <c>.git</c> removed, for Snyk's <c>--remote-repo-url</c>. Snyk uses
        /// this value verbatim as the target name, so a <c>.git</c> suffix surfaces as a confusing
        /// <c>owner/repo.git</c> target in the UI — distinct from the <c>owner/repo</c> target other tools create.
        /// </summary>
        public string RemoteRepoUrl => NormalizeRemoteRepoUrl(CloneUrl);

        /// <summary>
        /// Strips a trailing <c>.git</c> so a clone URL matches the target name Snyk stores from
        /// <c>--remote-repo-url</c>. Shared with branch-deletion cleanup, which resolves the same target
        /// from a webhook's repository clone URL.
        /// </summary>
        public static string NormalizeRemoteRepoUrl(string cloneUrl) =>
            cloneUrl.EndsWith(".git", StringComparison.OrdinalIgnoreCase) ? cloneUrl[..^4] : cloneUrl;
    }
}
