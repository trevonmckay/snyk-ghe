using GitHubJwt;
using Microsoft.Extensions.Options;
using Octokit;
using SnykGhe.Core.Configuration;
using SnykGhe.Core.Storage;

namespace SnykGhe.Core.GitHub
{
    /// <summary>
    /// Credentials for a single GitHub App installation: an Octokit client scoped to the
    /// installation, plus the raw access token (needed for authenticated git clone).
    /// </summary>
    public sealed record InstallationCredentials
    {
        public required GitHubClient Client { get; init; }

        public required string Token { get; init; }
    }

    /// <summary>
    /// Mints GitHub App JWTs and per-installation access tokens against the ghe.com tenant.
    /// </summary>
    public sealed class GitHubClientFactory
    {
        private readonly GitHubOptions _options;
        private readonly IAppConfigStore _appConfig;
        private readonly SemaphoreSlim _appIdLock = new(1, 1);
        private int _resolvedAppId;

        public GitHubClientFactory(IOptions<GitHubOptions> options, IAppConfigStore appConfig)
        {
            _options = options.Value;
            _appConfig = appConfig;
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

        /// <summary>
        /// Resolves the App ID, preferring an explicit <c>GitHub:AppId</c> config value and otherwise the
        /// value the registration flow persisted to the app-config store. A non-positive configured value
        /// (e.g. the unset default) is treated as absent. Cached after the first successful resolution.
        /// </summary>
        private async Task<int> ResolveAppIdAsync(CancellationToken cancellationToken)
        {
            if (_resolvedAppId > 0)
            {
                return _resolvedAppId;
            }

            await _appIdLock.WaitAsync(cancellationToken);
            try
            {
                if (_resolvedAppId > 0)
                {
                    return _resolvedAppId;
                }

                if (int.TryParse(_options.AppId, out var configured) && configured > 0)
                {
                    _resolvedAppId = configured;
                    return _resolvedAppId;
                }

                var stored = await _appConfig.GetAppIdAsync(cancellationToken);
                if (int.TryParse(stored, out var fromStore) && fromStore > 0)
                {
                    _resolvedAppId = fromStore;
                    return _resolvedAppId;
                }

                throw new InvalidOperationException(
                    "GitHub App ID is not configured (GitHub:AppId) and was not found in storage. " +
                    "Register the App at /api/github/app/register.");
            }
            finally
            {
                _appIdLock.Release();
            }
        }

        private string CreateAppJwt(int gitHubAppId)
        {
            // GitHub caps App JWTs at 10 minutes; stay under it to allow for clock skew.
            var factory = new GitHubJwtFactory(
                CreateKeySource(),
                new GitHubJwtFactoryOptions
                {
                    AppIntegrationId = gitHubAppId,
                    ExpirationSeconds = 540,
                });

            return factory.CreateEncodedJwtToken();
        }

        private GitHubClient CreateClient(Credentials credentials)
        {
            if (string.IsNullOrWhiteSpace(_options.ApiBaseUrl))
            {
                throw new InvalidOperationException("The GitHub API base URL is not configured. Set GitHub:ApiBaseUrl to the tenant API endpoint.");
            }

            return new(new ProductHeaderValue(_options.ProductName), new Uri(_options.ApiBaseUrl))
            {
                Credentials = credentials,
            };
        }

        /// <summary>Client authenticated as the App itself (for App-level endpoints).</summary>
        private GitHubClient CreateAppClient(int gitHubAppId)
        {
            return CreateClient(new Credentials(CreateAppJwt(gitHubAppId), AuthenticationType.Bearer));
        }

        /// <summary>Exchanges the App JWT for an installation token and returns a scoped client.</summary>
        public async Task<InstallationCredentials> CreateInstallationClientAsync(
            long installationId, CancellationToken cancellationToken = default)
        {
            var appId = await ResolveAppIdAsync(cancellationToken);
            var appClient = CreateAppClient(appId);
            AccessToken token = await appClient.GitHubApps.CreateInstallationToken(installationId);
            return new InstallationCredentials { Client = CreateClient(new Credentials(token.Token)), Token = token.Token };
        }
    }
}
