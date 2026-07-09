using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Extensions.Options;
using SnykGhe.Core.Configuration;

namespace SnykGhe.Core.Secrets
{
    /// <summary>
    /// Writes generated App credentials to Azure Key Vault under the names the deploy template references,
    /// so the values are picked up on the next revision restart. Authentication is managed identity.
    /// </summary>
    public sealed class KeyVaultAppCredentialStore : IAppCredentialStore
    {
        private readonly SecretClient _client;
        private readonly SecretRepositoryOptions _options;

        public KeyVaultAppCredentialStore(IOptions<SecretRepositoryOptions> options)
        {
            _options = options.Value;
            _client = new SecretClient(new Uri(_options.KeyVaultUri!), new DefaultAzureCredential());
        }

        public bool PersistsSecrets => true;

        public string Describe() => $"Azure Key Vault ({new Uri(_options.KeyVaultUri!).Host})";

        public async Task WriteAsync(AppCredentials credentials, CancellationToken cancellationToken = default)
        {
            await _client.SetSecretAsync(_options.PrivateKeySecretName, credentials.PrivateKeyPem, cancellationToken);

            if (!string.IsNullOrEmpty(credentials.WebhookSecret))
            {
                await _client.SetSecretAsync(_options.WebhookSecretName, credentials.WebhookSecret, cancellationToken);
            }
        }
    }
}
