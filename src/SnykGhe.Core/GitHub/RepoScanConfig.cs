namespace SnykGhe.Core.GitHub
{
    /// <summary>
    /// Per-repository scan overrides, layered on top of the org-level policy by the resolver. A general
    /// override bucket keyed by org + repo; today it carries only the additional Snyk <c>--exclude</c>
    /// directory/file names that apply to this repo in addition to the org's list.
    /// </summary>
    public sealed class RepoScanConfig
    {
        /// <summary>GitHub org login in original casing.</summary>
        public string GitHubOrg { get; set; } = string.Empty;

        /// <summary>Repository name (without owner) in original casing.</summary>
        public string Repo { get; set; } = string.Empty;

        public IReadOnlyList<string> ExcludeDirs { get; set; } = [];
    }
}
