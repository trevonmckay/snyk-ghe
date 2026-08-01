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

        public async Task SetOrgPolicyAsync(string gitHubOrg, OrgPolicyOverlay overlay, CancellationToken cancellationToken)
        {
            // Read-modify-write with Replace: Merge cannot clear a property, so to make a null overlay field
            // actually reset the override we rewrite the whole entity. The seeded GitHub fields are read back
            // from the existing row (or defaulted for an admin-created row) so Replace preserves them.
            var key = Normalize(gitHubOrg);
            var existing = await _table.GetEntityIfExistsAsync<GitHubInstallationRecordEntity>(
                GitHubInstallationRecordEntity.Partition, key, cancellationToken: cancellationToken);

            var entity = existing.HasValue && existing.Value is { } current
                ? current
                : new GitHubInstallationRecordEntity { RowKey = key, GitHubOrg = gitHubOrg };

            if (string.IsNullOrEmpty(entity.GitHubOrg))
            {
                entity.GitHubOrg = gitHubOrg;
            }

            entity.SnykOrgId = overlay.SnykOrgId;
            entity.SeverityThreshold = overlay.SeverityThreshold;
            entity.Ecosystem = overlay.Ecosystem;
            entity.Suspended = overlay.Suspended;
            entity.ExcludeDirs = ExcludeList.Join(overlay.ExcludeDirs);

            await _table.UpsertEntityAsync(entity, TableUpdateMode.Replace, cancellationToken);
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

        private static string RepoRowKey(string gitHubOrg, string repo) =>
            $"{Normalize(gitHubOrg)}/{repo.ToLowerInvariant()}";

        public async Task<RepoScanConfig?> FindRepoConfigAsync(string gitHubOrg, string repo, CancellationToken cancellationToken)
        {
            var response = await _table.GetEntityIfExistsAsync<RepoScanConfigEntity>(
                RepoScanConfigEntity.Partition, RepoRowKey(gitHubOrg, repo), cancellationToken: cancellationToken);

            if (!response.HasValue || response.Value is not { } entity)
            {
                return null;
            }

            return new RepoScanConfig
            {
                GitHubOrg = entity.GitHubOrg,
                Repo = entity.Repo,
                ExcludeDirs = ExcludeList.Split(entity.ExcludeDirs),
            };
        }

        public async Task SetRepoConfigAsync(string gitHubOrg, string repo, IReadOnlyList<string> excludeDirs, CancellationToken cancellationToken)
        {
            var entity = new RepoScanConfigEntity
            {
                RowKey = RepoRowKey(gitHubOrg, repo),
                GitHubOrg = gitHubOrg,
                Repo = repo,
                ExcludeDirs = ExcludeList.Join(excludeDirs),
            };

            await _table.UpsertEntityAsync(entity, TableUpdateMode.Replace, cancellationToken);
        }

        public async Task RemoveRepoConfigAsync(string gitHubOrg, string repo, CancellationToken cancellationToken)
        {
            await _table.DeleteEntityAsync(RepoScanConfigEntity.Partition, RepoRowKey(gitHubOrg, repo), ETag.All, cancellationToken);
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
                ExcludeDirs = ExcludeList.Split(entity.ExcludeDirs),
            };
        }
    }
}
