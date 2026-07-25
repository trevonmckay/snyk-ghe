using Microsoft.Extensions.Options;
using Snyk.Client;
using SnykGhe.Core.Configuration;

namespace SnykGhe.Core.Snyk
{
    /// <summary>
    /// Supplies <see cref="SnykApiClient"/> with a bearer token, preferring the OAuth client-credentials
    /// service account and falling back to a static service-account token. Snyk's REST API accepts either,
    /// but the OAuth exchange is the hardened path and the only one that rotates.
    /// </summary>
    public sealed class SnykApiTokenProvider : ISnykTokenProvider
    {
        private readonly SnykOAuthTokenProvider _oauthTokenProvider;
        private readonly SnykOptions _options;

        public SnykApiTokenProvider(SnykOAuthTokenProvider oauthTokenProvider, IOptions<SnykOptions> options)
        {
            _oauthTokenProvider = oauthTokenProvider;
            _options = options.Value;
        }

        public async ValueTask<SnykCredential> GetCredentialAsync(CancellationToken cancellationToken = default)
        {
            if (_oauthTokenProvider.IsConfigured)
            {
                return SnykCredential.Bearer(await _oauthTokenProvider.GetAccessTokenAsync(cancellationToken));
            }

            if (!string.IsNullOrWhiteSpace(_options.Token))
            {
                return SnykCredential.ApiToken(_options.Token!);
            }

            throw new InvalidOperationException(
                "No Snyk credentials are configured: set Snyk:OAuthClientId/OAuthClientSecret, or Snyk:Token.");
        }
    }
}
