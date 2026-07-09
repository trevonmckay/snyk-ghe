using Azure;
using Azure.Data.Tables;
using Azure.Identity;
using Microsoft.Extensions.Options;
using SnykGhe.Core.Configuration;
using SnykGhe.Core.GitHub;

namespace SnykGhe.Core.Storage
{
    public sealed class TableStorageGitHubInstallationRegistry : IGitHubInstallationRegistry
    {
        private readonly TableClient _table;

        public TableStorageGitHubInstallationRegistry(IOptions<StorageOptions> options)
        {
            var config = options.Value;

            _table = !string.IsNullOrWhiteSpace(config.TableServiceUri)
                ? new TableClient(new Uri(config.TableServiceUri), config.TableName, new DefaultAzureCredential())
                : new TableClient(config.ConnectionString, config.TableName);
        }

        public async Task EnsureCreatedAsync(CancellationToken cancellationToken)
        {
            await _table.CreateIfNotExistsAsync(cancellationToken);
        }

        private static string Normalize(string gitHubOrg)
        {
            return gitHubOrg.ToLowerInvariant();
        }

        public async Task SeedAsync(long installationId, string gitHubOrg, long accountId, CancellationToken cancellationToken)
        {
            // Merge: null Snyk mapping / policy properties are omitted, so a re-install keeps an existing mapping.
            var entity = new GitHubInstallationRecordEntity
            {
                RowKey = Normalize(gitHubOrg),
                InstallationId = installationId,
                GitHubOrg = gitHubOrg,
                AccountId = accountId,
                Suspended = false,
            };

            await _table.UpsertEntityAsync(entity, TableUpdateMode.Merge, cancellationToken);
        }

        public async Task SetMappingAsync(string gitHubOrg, string snykOrgId, string? severityThreshold, string? ecosystem, CancellationToken cancellationToken)
        {
            // A typed entity would serialize its value-type properties (InstallationId, AccountId, Suspended)
            // as 0 / false even when unset, and Merge would overwrite the seeded GitHub values. Write a
            // partial entity carrying only the mapping properties so Merge leaves everything else intact.
            var entity = new TableEntity(GitHubInstallationRecordEntity.Partition, Normalize(gitHubOrg))
            {
                ["GitHubOrg"] = gitHubOrg,
                ["SnykOrgId"] = snykOrgId,
            };

            if (!string.IsNullOrWhiteSpace(severityThreshold))
            {
                entity["SeverityThreshold"] = severityThreshold;
            }

            if (!string.IsNullOrWhiteSpace(ecosystem))
            {
                entity["Ecosystem"] = ecosystem;
            }

            await _table.UpsertEntityAsync(entity, TableUpdateMode.Merge, cancellationToken);
        }

        public async Task SetSuspendedAsync(string gitHubOrg, bool suspended, CancellationToken cancellationToken)
        {
            // Partial entity (see SetMappingAsync) — only Suspended is written, so Merge leaves the seeded
            // GitHub install fields untouched.
            var entity = new TableEntity(GitHubInstallationRecordEntity.Partition, Normalize(gitHubOrg))
            {
                ["GitHubOrg"] = gitHubOrg,
                ["Suspended"] = suspended,
            };

            await _table.UpsertEntityAsync(entity, TableUpdateMode.Merge, cancellationToken);
        }

        public async Task RemoveAsync(string gitHubOrg, CancellationToken cancellationToken)
        {
            await _table.DeleteEntityAsync(GitHubInstallationRecordEntity.Partition, Normalize(gitHubOrg), ETag.All, cancellationToken);
        }

        public async Task<GitHubInstallationRecord?> FindAsync(string gitHubOrg, CancellationToken cancellationToken)
        {
            var response = await _table.GetEntityIfExistsAsync<GitHubInstallationRecordEntity>(
                GitHubInstallationRecordEntity.Partition, Normalize(gitHubOrg), cancellationToken: cancellationToken);

            if (!response.HasValue || response.Value is not { } entity)
            {
                return null;
            }

            return new GitHubInstallationRecord
            {
                InstallationId = entity.InstallationId,
                GitHubOrg = entity.GitHubOrg,
                AccountId = entity.AccountId,
                SnykOrgId = entity.SnykOrgId,
                SeverityThreshold = entity.SeverityThreshold,
                Ecosystem = entity.Ecosystem,
                Suspended = entity.Suspended,
            };
        }
    }
}
