using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Snyk.Client.Resources;
using Snyk.Client.Tests;

namespace Snyk.Client
{
    /// <summary>
    /// Client for the Snyk REST API, grouped by resource. Concrete by design: it is exercised in tests by
    /// substituting the <see cref="HttpMessageHandler"/> behind its named <see cref="HttpClient"/>, which
    /// covers request shape and response parsing that an interface seam would hide.
    /// </summary>
    public sealed class SnykApiClient
    {
        /// <summary>Named client for ordinary calls.</summary>
        public const string HttpClientName = "snyk-api";

        /// <summary>
        /// Named client configured not to follow redirects. The Test API signals completion with a 303 whose
        /// Location carries the test id; an auto-following client would swallow it.
        /// </summary>
        public const string NoRedirectHttpClientName = "snyk-api-noredirect";

        private readonly SnykHttpTransport _transport;

        public SnykApiClient(
            IHttpClientFactory httpClientFactory,
            ISnykTokenProvider tokenProvider,
            IOptions<SnykApiOptions> options,
            ILogger<SnykApiClient>? logger = null)
        {
            _transport = new SnykHttpTransport(
                httpClientFactory,
                tokenProvider,
                options.Value,
                logger ?? NullLogger<SnykApiClient>.Instance);

            Tests = new SnykTestsApi(_transport, logger ?? NullLogger<SnykApiClient>.Instance);
            Orgs = new SnykOrgsApi(_transport);
            Projects = new SnykProjectsApi(_transport);
            Targets = new SnykTargetsApi(_transport);
        }

        /// <summary>The Test API: submit content for scanning and read findings.</summary>
        public SnykTestsApi Tests { get; }

        public SnykOrgsApi Orgs { get; }

        public SnykProjectsApi Projects { get; }

        public SnykTargetsApi Targets { get; }
    }
}
