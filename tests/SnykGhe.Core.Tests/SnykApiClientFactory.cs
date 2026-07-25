using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Snyk.Client;
using SnykGhe.Core.Configuration;
using SnykGhe.Core.Snyk;

namespace SnykGhe.Core.Tests
{
    /// <summary>
    /// Builds a <see cref="SnykApiClient"/> over a stub <see cref="IHttpClientFactory"/>, wired to the same
    /// credential provider and option mapping the application uses.
    /// </summary>
    internal static class SnykApiClientFactory
    {
        internal static SnykApiClient Create(IHttpClientFactory httpClientFactory, SnykOptions snyk)
        {
            var oauth = new SnykOAuthTokenProvider(
                httpClientFactory, Options.Create(snyk), NullLogger<SnykOAuthTokenProvider>.Instance);

            var credentials = new SnykApiTokenProvider(oauth, Options.Create(snyk));

            var apiOptions = Options.Create(new SnykApiOptions
            {
                BaseUrl = snyk.ApiBaseUrl,
                ApiVersion = snyk.RestApiVersion,
                TestPollInterval = TimeSpan.Zero,
            });

            return new SnykApiClient(httpClientFactory, credentials, apiOptions, NullLogger<SnykApiClient>.Instance);
        }
    }
}
