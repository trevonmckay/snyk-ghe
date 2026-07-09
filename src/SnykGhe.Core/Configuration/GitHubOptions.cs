namespace SnykGhe.Core.Configuration
{
    /// <summary>
    /// Configuration for the GitHub App that authenticates against a GitHub Enterprise
    /// Cloud with data residency tenant (ghe.com).
    /// </summary>
    public sealed class GitHubOptions
    {
        public const string SectionName = "GitHub";

        /// <summary>
        /// REST API base address for the ghe.com tenant. Data residency tenants expose the API
        /// at https://api.&lt;subdomain&gt;.ghe.com/ — NOT the GHES https://host/api/v3 pattern.
        /// Octokit uses this address verbatim, so it must include the trailing slash.
        /// </summary>
        public string? ApiBaseUrl { get; set; }

        /// <summary>Numeric GitHub App ID (App settings page).</summary>
        public string? AppId { get; set; }

        /// <summary>
        /// PEM-encoded private key for the GitHub App. Inject from Azure Key Vault as a secret;
        /// avoid committing it. Either this or <see cref="PrivateKeyPath"/> must be set.
        /// </summary>
        public string? PrivateKeyPem { get; set; }

        /// <summary>Filesystem path to the PEM private key (alternative to <see cref="PrivateKeyPem"/>).</summary>
        public string? PrivateKeyPath { get; set; }

        /// <summary>Shared secret configured on the App's webhook, used to validate signatures.</summary>
        public string WebhookSecret { get; set; } = string.Empty;

        /// <summary>User-Agent product name sent to GitHub.</summary>
        public string ProductName { get; set; } = "snyk-ghe-app";

        /// <summary>
        /// Base name for the Check Runs shown on pull requests. Each product scan prefixes its scan type,
        /// producing <c>sca/{CheckRunName}</c>, <c>sast/{CheckRunName}</c>, and <c>iac/{CheckRunName}</c>.
        /// </summary>
        public string CheckRunName { get; set; } = "snyk";
    }
}
