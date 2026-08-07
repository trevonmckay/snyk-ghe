using Azure;
using Azure.Data.Tables;

namespace SnykGhe.Core.Storage
{
    /// <summary>
    /// One row per repository that carries scan overrides, kept in its own partition so it never collides with
    /// the per-org installation rows. The row key is <c>"{org}/{repo}"</c> lower-cased.
    /// </summary>
    internal sealed class RepoScanConfigEntity : ITableEntity
    {
        public const string Partition = "repoconfig";

        public string PartitionKey { get; set; } = Partition;

        /// <summary>Normalized (lower-case) <c>"{org}/{repo}"</c>.</summary>
        public string RowKey { get; set; } = string.Empty;

        public ETag ETag { get; set; }

        public DateTimeOffset? Timestamp { get; set; }

        /// <summary>GitHub org login in original casing.</summary>
        public string GitHubOrg { get; set; } = string.Empty;

        /// <summary>Repository name (without owner) in original casing.</summary>
        public string Repo { get; set; } = string.Empty;

        /// <summary>Repo-level Snyk exclude names, stored newline-delimited (see <see cref="Configuration.ExcludeList"/>).</summary>
        public string? ExcludeDirs { get; set; }

        /// <summary>Repo-level base-branch scan patterns, stored newline-delimited (see <see cref="Configuration.BranchFilter"/>).</summary>
        public string? ScanTargetBranches { get; set; }
    }
}
