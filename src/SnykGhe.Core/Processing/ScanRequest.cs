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
        /// The clone URL with any trailing <c>.git</c> removed, for Snyk's <c>--remote-repo-url</c>. Snyk uses
        /// this value verbatim as the target name, so a <c>.git</c> suffix surfaces as a confusing
        /// <c>owner/repo.git</c> target in the UI — distinct from the <c>owner/repo</c> target other tools create.
        /// </summary>
        public string RemoteRepoUrl =>
            CloneUrl.EndsWith(".git", StringComparison.OrdinalIgnoreCase) ? CloneUrl[..^4] : CloneUrl;
    }
}
