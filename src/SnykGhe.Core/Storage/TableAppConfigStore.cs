using Azure;
using Azure.Data.Tables;
using Azure.Identity;
using Microsoft.Extensions.Options;
using SnykGhe.Core.Configuration;

namespace SnykGhe.Core.Storage
{
    /// <summary>App-level config row in Azure Table Storage, kept in its own partition so it never
    /// collides with the per-org installation rows.</summary>
    internal sealed class AppConfigEntity : ITableEntity
    {
        public const string Partition = "appconfig";

        public string PartitionKey { get; set; } = Partition;

        public string RowKey { get; set; } = string.Empty;

        public ETag ETag { get; set; }

        public DateTimeOffset? Timestamp { get; set; }

        public string? Value { get; set; }
    }

    /// <summary>Azure Table Storage implementation of <see cref="IAppConfigStore"/>, sharing the
    /// installations table and its managed-identity authentication.</summary>
    public sealed class TableAppConfigStore : IAppConfigStore
    {
        private const string AppIdRowKey = "github-app-id";

        private readonly TableClient _table;

        public TableAppConfigStore(IOptions<StorageOptions> options)
        {
            var config = options.Value;

            _table = !string.IsNullOrWhiteSpace(config.TableServiceUri)
                ? new TableClient(new Uri(config.TableServiceUri), config.TableName, new DefaultAzureCredential())
                : new TableClient(config.ConnectionString, config.TableName);
        }

        public async Task<string?> GetAppIdAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                var response = await _table.GetEntityIfExistsAsync<AppConfigEntity>(
                    AppConfigEntity.Partition, AppIdRowKey, cancellationToken: cancellationToken);

                return response.HasValue && response.Value is { } entity ? entity.Value : null;
            }
            catch (RequestFailedException ex) when (ex.Status == 404)
            {
                // Table not created yet (no installations and no registration); treat as unset.
                return null;
            }
        }

        public async Task SetAppIdAsync(string appId, CancellationToken cancellationToken = default)
        {
            await _table.UpsertEntityAsync(
                new AppConfigEntity { RowKey = AppIdRowKey, Value = appId },
                TableUpdateMode.Replace,
                cancellationToken);
        }
    }
}
