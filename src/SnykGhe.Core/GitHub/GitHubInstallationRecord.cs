namespace SnykGhe.Core.GitHub
{
    /// <summary>
    /// One row per GitHub org installation. GitHub-known fields (installation id, account) are seeded
    /// by the installation webhook; the Snyk mapping and policy overrides are set explicitly via the
    /// admin endpoint.
    /// </summary>
    public class GitHubInstallationRecord
    {
        public long InstallationId { get; set; }

        /// <summary>GitHub org login in original casing.</summary>
        public string GitHubOrg { get; set; } = string.Empty;

        public long AccountId { get; set; }

        /// <summary>Explicit Snyk org id this GitHub org's scans report to. Null until an admin sets it.</summary>
        public string? SnykOrgId { get; set; }

        public string? SeverityThreshold { get; set; }

        public string? Ecosystem { get; set; }

        public bool Suspended { get; set; }

        /// <summary>Org-level Snyk <c>--exclude</c> directory/file names, applied to every repo in the org.</summary>
        public IReadOnlyList<string> ExcludeDirs { get; set; } = [];

        /// <summary>
        /// Org-level base-branch scan patterns. When non-empty, overrides the global default for every repo in
        /// the org (a repo-level list overrides this in turn). Empty means "inherit". See
        /// <see cref="Configuration.BranchFilter"/>.
        /// </summary>
        public IReadOnlyList<string> ScanTargetBranches { get; set; } = [];
    }
}
