namespace SnykGhe.Core.Configuration
{
    /// <summary>Backing store for the installation registry.</summary>
    public enum StorageProvider
    {
        AzureTable,
        DynamoDb,
    }

    /// <summary>
    /// Configuration for the installation registry. The same app runs on Azure (Table Storage) or AWS
    /// (DynamoDB) by switching <see cref="Provider"/>; only the relevant fields are used per provider.
    /// </summary>
    public sealed class StorageOptions
    {
        public const string SectionName = "Storage";

        /// <summary>Which backing store to use.</summary>
        public StorageProvider Provider { get; set; } = StorageProvider.AzureTable;

        /// <summary>Table/collection name holding one row per GitHub org installation (both providers).</summary>
        public string TableName { get; set; } = "installations";

        /// <summary>
        /// Table/collection name for baseline-scan coordination (single-flight leases + latest-requested-commit
        /// per repo branch). Separate from <see cref="TableName"/>; both providers create it on startup.
        /// </summary>
        public string ScanCoordinationTableName { get; set; } = "scancoordination";

        /// <summary>Create the table at startup if it does not exist (mirrors local-dev convenience).</summary>
        public bool CreateTableIfMissing { get; set; } = true;

        // --- Azure Table Storage ---

        /// <summary>Table service endpoint, e.g. https://account.table.core.windows.net. Uses managed identity.</summary>
        public string? TableServiceUri { get; set; }

        /// <summary>Storage connection string (local dev / non-managed-identity scenarios).</summary>
        public string? ConnectionString { get; set; }

        // --- AWS DynamoDB ---

        /// <summary>AWS region for DynamoDB. Falls back to the SDK's default resolution (AWS_REGION) when empty.</summary>
        public string? AwsRegion { get; set; }

        // --- Admin endpoint ---

        /// <summary>
        /// API key required (in the X-Admin-Key header) to set per-org Snyk mappings.
        /// Empty disables the admin endpoint entirely (closed by default). Front with Entra / Easy Auth
        /// or equivalent in production; this is a defense-in-depth secondary control.
        /// </summary>
        public string? AdminApiKey { get; set; }
    }
}
