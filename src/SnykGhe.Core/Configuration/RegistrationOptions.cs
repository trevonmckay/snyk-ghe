namespace SnykGhe.Core.Configuration
{
    /// <summary>
    /// Configuration for the self-service GitHub App registration flow (manifest creation + post-install
    /// setup page). The flow is disabled unless the admin key (<see cref="StorageOptions.AdminApiKey"/>)
    /// is set, since registration writes App credentials to the secret store.
    /// </summary>
    public sealed class RegistrationOptions
    {
        public const string SectionName = "Registration";

        /// <summary>Name pre-filled in the manifest; the operator can still rename on GitHub's confirmation page.</summary>
        public string AppName { get; set; } = "snyk-ghe";

        /// <summary>
        /// This service's externally reachable base URL (e.g. <c>https://snyk-ghe.example.com</c>), used to
        /// build the webhook, redirect, and setup URLs in the manifest. Falls back to the incoming request's
        /// scheme + host when empty, which is correct when the service is reached directly.
        /// </summary>
        public string? PublicBaseUrl { get; set; }
    }
}
