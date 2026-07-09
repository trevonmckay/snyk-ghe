using Amazon.SecretsManager;
using Amazon.SecretsManager.Model;
using Microsoft.Extensions.Options;
using SnykGhe.Core.Configuration;

namespace SnykGhe.Core.Secrets
{
    /// <summary>
    /// Writes generated App credentials to AWS Secrets Manager under the names the CloudFormation template
    /// references, so the values are picked up on the next App Runner restart. Authentication uses the
    /// default AWS credential chain (the instance role). Secrets are updated in place, or created if absent.
    /// </summary>
    public sealed class SecretsManagerAppCredentialStore : IAppCredentialStore
    {
        private readonly IAmazonSecretsManager _client;
        private readonly SecretRepositoryOptions _options;

        public SecretsManagerAppCredentialStore(IAmazonSecretsManager client, IOptions<SecretRepositoryOptions> options)
        {
            _client = client;
            _options = options.Value;
        }

        public bool PersistsSecrets => true;

        public string Describe() => "AWS Secrets Manager";

        public async Task WriteAsync(AppCredentials credentials, CancellationToken cancellationToken = default)
        {
            var prefix = _options.AwsSecretPrefix ?? string.Empty;

            await PutAsync(prefix + _options.PrivateKeySecretName, credentials.PrivateKeyPem, cancellationToken);

            if (!string.IsNullOrEmpty(credentials.WebhookSecret))
            {
                await PutAsync(prefix + _options.WebhookSecretName, credentials.WebhookSecret, cancellationToken);
            }
        }

        private async Task PutAsync(string secretId, string value, CancellationToken cancellationToken)
        {
            try
            {
                await _client.PutSecretValueAsync(
                    new PutSecretValueRequest { SecretId = secretId, SecretString = value },
                    cancellationToken);
            }
            catch (ResourceNotFoundException)
            {
                await _client.CreateSecretAsync(
                    new CreateSecretRequest { Name = secretId, SecretString = value },
                    cancellationToken);
            }
        }
    }
}
