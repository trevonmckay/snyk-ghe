using GitHubJwt;
using Microsoft.Extensions.Options;
using Octokit;
using SnykGhe.WebhookService.Configuration;

namespace SnykGhe.WebhookService.GitHub
{
    /// <summary>
    /// Credentials for a single GitHub App installation: an Octokit client scoped to the
    /// installation, plus the raw access token (needed for authenticated git clone).
    /// </summary>
    public sealed record InstallationCredentials(GitHubClient Client, string Token);

    /// <summary>
    /// Mints GitHub App JWTs and per-installation access tokens against the ghe.com tenant.
    /// </summary>
    public sealed class GitHubClientFactory
    {
        private readonly GitHubOptions _options;

        public GitHubClientFactory(IOptions<GitHubOptions> options)
        {
            _options = options.Value;
        }

        private IPrivateKeySource CreateKeySource()
        {
            if (!string.IsNullOrWhiteSpace(_options.PrivateKeyPem))
            {
                return new StringPrivateKeySource(_options.PrivateKeyPem);
            }

            if (!string.IsNullOrWhiteSpace(_options.PrivateKeyPath))
            {
                return new FilePrivateKeySource(_options.PrivateKeyPath);
            }

            throw new InvalidOperationException(
                "No GitHub App private key configured. Set GitHub:PrivateKeyPem or GitHub:PrivateKeyPath.");
        }

        private string CreateAppJwt()
        {
            // GitHub caps App JWTs at 10 minutes; stay under it to allow for clock skew.
            var factory = new GitHubJwtFactory(
                CreateKeySource(),
                new GitHubJwtFactoryOptions
                {
                    AppIntegrationId = _options.AppId,
                    ExpirationSeconds = 540,
                });

            return factory.CreateEncodedJwtToken();
        }

        private GitHubClient CreateClient(Credentials credentials)
        {
            return new(new ProductHeaderValue(_options.ProductName), new Uri(_options.ApiBaseUrl))
            {
                Credentials = credentials,
            };
        }

        /// <summary>Client authenticated as the App itself (for App-level endpoints).</summary>
        public GitHubClient CreateAppClient()
        {
            return CreateClient(new Credentials(CreateAppJwt(), AuthenticationType.Bearer));
        }

        /// <summary>Exchanges the App JWT for an installation token and returns a scoped client.</summary>
        public async Task<InstallationCredentials> CreateInstallationClientAsync(long installationId)
        {
            var appClient = CreateAppClient();
            AccessToken token = await appClient.GitHubApps.CreateInstallationToken(installationId);
            return new InstallationCredentials(CreateClient(new Credentials(token.Token)), token.Token);
        }
    }
}
