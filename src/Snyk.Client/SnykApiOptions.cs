namespace Snyk.Client
{
    /// <summary>Connection and polling settings for <see cref="SnykApiClient"/>.</summary>
    public sealed class SnykApiOptions
    {
        public const string SectionName = "SnykApi";

        /// <summary>
        /// Base URL of the Snyk REST API. Defaults to the US region; override for EU/AU tenants
        /// (e.g. <c>https://api.eu.snyk.io</c>).
        /// </summary>
        public string BaseUrl { get; set; } = "https://api.snyk.io";

        /// <summary>
        /// Date-stamped REST API version sent as the required <c>version</c> query parameter. Must be a GA
        /// version: the Test API endpoints are not served on <c>~beta</c> or <c>~experimental</c> channels,
        /// which return 404 for an otherwise valid request.
        /// </summary>
        public string ApiVersion { get; set; } = "2026-03-25";

        /// <summary>How long to wait between polls of a test job.</summary>
        public TimeSpan TestPollInterval { get; set; } = TimeSpan.FromSeconds(5);

        /// <summary>Maximum time to wait for a test job to reach a terminal state.</summary>
        public TimeSpan TestTimeout { get; set; } = TimeSpan.FromMinutes(20);

        /// <summary>Page size for paginated collection reads. The API rejects values below 10.</summary>
        public int PageSize { get; set; } = 100;
    }
}
