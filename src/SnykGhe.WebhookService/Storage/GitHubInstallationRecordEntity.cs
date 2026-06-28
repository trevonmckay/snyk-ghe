using Azure;
using Azure.Data.Tables;

namespace SnykGhe.WebhookService.Storage
{
    /// <summary>
    /// One row per GitHub org installation. GitHub-known fields (installation id, account) are seeded
    /// by the installation webhook; the Snyk mapping and policy overrides are set explicitly via the
    /// admin endpoint. All rows share a single partition (org count is small).
    /// </summary>
    internal sealed class GitHubInstallationRecordEntity : ITableEntity
    {
        public const string Partition = "installation";

        public string PartitionKey { get; set; } = Partition;

        /// <summary>Normalized (lower-case) GitHub org login.</summary>
        public string RowKey { get; set; } = string.Empty;

        public ETag ETag { get; set; }

        public DateTimeOffset? Timestamp { get; set; }

        public long InstallationId { get; set; }

        /// <summary>GitHub org login in original casing.</summary>
        public string GitHubOrg { get; set; } = string.Empty;

        public long AccountId { get; set; }

        /// <summary>Explicit Snyk org id this GitHub org's scans report to. Null until an admin sets it.</summary>
        public string? SnykOrgId { get; set; }

        public string? SeverityThreshold { get; set; }

        public string? Ecosystem { get; set; }

        public bool Suspended { get; set; }
    }
}
