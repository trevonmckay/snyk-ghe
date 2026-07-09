using System.Security.Cryptography;
using System.Text;
using Azure;
using Azure.Data.Tables;
using Azure.Identity;
using Microsoft.Extensions.Options;
using SnykGhe.Core.Configuration;

namespace SnykGhe.Core.Storage
{
    /// <summary>
    /// Azure Table Storage coordination store. One entity per <c>{owner}/{repo}#{branch}</c>, keyed by a hash
    /// of the branch key (the raw key contains '/' and '#', which are invalid in a Table RowKey). Optimistic
    /// concurrency via ETag gives the compare-and-set the single-flight lease needs.
    /// </summary>
    public sealed class TableStorageScanCoordinationStore : IScanCoordinationStore
    {
        private const string Partition = "scan";
        private const int MaxAttempts = 8;

        private readonly TableClient _table;

        public TableStorageScanCoordinationStore(IOptions<StorageOptions> options)
        {
            var config = options.Value;
            _table = !string.IsNullOrWhiteSpace(config.TableServiceUri)
                ? new TableClient(new Uri(config.TableServiceUri), config.ScanCoordinationTableName, new DefaultAzureCredential())
                : new TableClient(config.ConnectionString, config.ScanCoordinationTableName);
        }

        public async Task EnsureCreatedAsync(CancellationToken cancellationToken)
        {
            await _table.CreateIfNotExistsAsync(cancellationToken);
        }

        // RowKey cannot contain '/', '\', '#', '?'; branch keys routinely do. Hash to a safe fixed-length key.
        private static string RowKeyFor(string key)
        {
            var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(key.ToLowerInvariant()));
            return Convert.ToHexString(bytes);
        }

        public async Task<ScanClaim> TryAcquireAsync(string key, string requestedSha, string leaseToken, TimeSpan lease, CancellationToken cancellationToken)
        {
            var rowKey = RowKeyFor(key);

            for (var attempt = 0; attempt < MaxAttempts; attempt++)
            {
                var now = DateTimeOffset.UtcNow;
                var existing = await _table.GetEntityIfExistsAsync<TableEntity>(Partition, rowKey, cancellationToken: cancellationToken);

                if (!existing.HasValue || existing.Value is not { } entity)
                {
                    var created = new TableEntity(Partition, rowKey)
                    {
                        ["Key"] = key,
                        ["RequestedSha"] = requestedSha,
                        ["RequestedAt"] = now,
                        ["LeaseOwner"] = leaseToken,
                        ["LeaseUntil"] = now + lease,
                    };

                    try
                    {
                        await _table.AddEntityAsync(created, cancellationToken);
                        return ScanClaim.Acquired;
                    }
                    catch (RequestFailedException ex) when (ex.Status == 409)
                    {
                        continue; // lost the create race; re-read and evaluate the lease
                    }
                }

                if (entity.GetString("LastScannedSha") == requestedSha)
                {
                    return ScanClaim.AlreadyScanned; // redelivery or a commit the in-flight scan already covered
                }

                var leaseFree = entity.GetDateTimeOffset("LeaseUntil") is not { } until || until <= now;

                entity["RequestedSha"] = requestedSha;
                entity["RequestedAt"] = now;
                if (leaseFree)
                {
                    entity["LeaseOwner"] = leaseToken;
                    entity["LeaseUntil"] = now + lease;
                }

                try
                {
                    await _table.UpdateEntityAsync(entity, entity.ETag, TableUpdateMode.Replace, cancellationToken);
                    return leaseFree ? ScanClaim.Acquired : ScanClaim.Coalesced;
                }
                catch (RequestFailedException ex) when (ex.Status == 412)
                {
                    continue; // concurrent writer; retry
                }
            }

            throw new InvalidOperationException($"Could not acquire scan coordination lease for '{key}' after {MaxAttempts} attempts.");
        }

        public async Task<string?> CompletePassAsync(string key, string leaseToken, string requestedSha, string scannedSha, TimeSpan lease, CancellationToken cancellationToken)
        {
            var rowKey = RowKeyFor(key);

            for (var attempt = 0; attempt < MaxAttempts; attempt++)
            {
                var now = DateTimeOffset.UtcNow;
                var existing = await _table.GetEntityIfExistsAsync<TableEntity>(Partition, rowKey, cancellationToken: cancellationToken);
                if (!existing.HasValue || existing.Value is not { } entity)
                {
                    return null;
                }

                if (entity.GetString("LeaseOwner") != leaseToken)
                {
                    return null; // lease lost (stolen after expiry) — leave the current holder's state alone
                }

                entity["LastScannedSha"] = scannedSha;

                var requested = entity.GetString("RequestedSha");
                var hasNewer = requested is not null && requested != requestedSha;

                if (hasNewer)
                {
                    entity["LeaseUntil"] = now + lease; // renew and keep the lease for another pass
                }
                else
                {
                    entity["LeaseOwner"] = string.Empty; // release atomically with the "nothing new" decision
                    entity["LeaseUntil"] = now;
                }

                try
                {
                    await _table.UpdateEntityAsync(entity, entity.ETag, TableUpdateMode.Replace, cancellationToken);
                    return hasNewer ? requested : null;
                }
                catch (RequestFailedException ex) when (ex.Status == 412)
                {
                    continue; // a push landed concurrently; retry and re-evaluate
                }
            }

            return null; // could not commit; let the lease expire
        }

        public async Task ReleaseAsync(string key, string leaseToken, CancellationToken cancellationToken)
        {
            var rowKey = RowKeyFor(key);

            for (var attempt = 0; attempt < MaxAttempts; attempt++)
            {
                var existing = await _table.GetEntityIfExistsAsync<TableEntity>(Partition, rowKey, cancellationToken: cancellationToken);
                if (!existing.HasValue || existing.Value is not { } entity)
                {
                    return;
                }

                if (entity.GetString("LeaseOwner") != leaseToken)
                {
                    return; // not ours (already released or stolen)
                }

                entity["LeaseOwner"] = string.Empty;
                entity["LeaseUntil"] = DateTimeOffset.UtcNow; // immediately expired → free for the next request
                try
                {
                    await _table.UpdateEntityAsync(entity, entity.ETag, TableUpdateMode.Replace, cancellationToken);
                    return;
                }
                catch (RequestFailedException ex) when (ex.Status == 412)
                {
                    continue;
                }
            }
        }
    }
}
