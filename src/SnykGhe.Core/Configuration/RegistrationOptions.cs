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
        /// build the redirect and setup URLs in the manifest (and the webhook URL when <see cref="WebhookUrl"/>
        /// is unset). Falls back to the incoming request's scheme + host when empty, which is correct when the
        /// service is reached directly.
        /// </summary>
        public string? PublicBaseUrl { get; set; }

        /// <summary>
        /// Absolute webhook URL to declare in the manifest's <c>hook_attributes</c>, used when the public
        /// webhook endpoint is a different host than this service. In the scale-to-zero topology an Azure
        /// Function front-ends webhooks while registration runs on the Container App, so the manifest's
        /// webhook URL must point at the Function, not the registration host. Falls back to
        /// <c>{PublicBaseUrl}/api/github/webhooks</c> when empty (correct for the always-on topology, where the
        /// service is itself the webhook endpoint).
        /// </summary>
        public string? WebhookUrl { get; set; }
    }
}
