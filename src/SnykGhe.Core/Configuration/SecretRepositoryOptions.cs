namespace SnykGhe.Core.Configuration
{
    /// <summary>Secret repository that the registration flow writes generated App credentials to.</summary>
    public enum SecretStoreProvider
    {
        /// <summary>No persistent store; credentials are shown once for the operator to copy (local/dev).</summary>
        None,
        AzureKeyVault,
        AwsSecretsManager,
    }

    /// <summary>
    /// Where the manifest-registration flow writes the generated private key and webhook secret. The App ID
    /// is public (not stored here). The secret names match the deploy templates so a restart picks the
    /// values up. Authentication is the platform's managed identity (no connection strings / access keys).
    /// </summary>
    public sealed class SecretRepositoryOptions
    {
        public const string SectionName = "SecretRepository";

        public SecretStoreProvider Provider { get; set; } = SecretStoreProvider.None;

        /// <summary>Key Vault URI, e.g. <c>https://my-vault.vault.azure.net/</c> (AzureKeyVault only).</summary>
        public string? KeyVaultUri { get; set; }

        /// <summary>AWS region. Falls back to the SDK's default resolution (AWS_REGION) when empty.</summary>
        public string? AwsRegion { get; set; }

        /// <summary>Prefix applied to AWS Secrets Manager secret names (Azure Key Vault names have no prefix).</summary>
        public string AwsSecretPrefix { get; set; } = "snyk-ghe/";

        public string PrivateKeySecretName { get; set; } = "github-app-private-key";

        public string WebhookSecretName { get; set; } = "github-webhook-secret";

        public bool IsConfigured => Provider != SecretStoreProvider.None;
    }
}
