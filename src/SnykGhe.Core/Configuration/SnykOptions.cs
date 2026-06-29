namespace SnykGhe.Core.Configuration
{
    /// <summary>
    /// Snyk CLI configuration. Authentication is global (one group-level service account spans every
    /// Snyk org); per-GitHub-org targeting and policy live in <see cref="Orgs"/> and the Default* values.
    /// </summary>
    public sealed class SnykOptions
    {
        public const string SectionName = "Snyk";

        /// <summary>Path to the Snyk standalone CLI binary inside the container.</summary>
        public string CliPath { get; set; } = "snyk";

        /// <summary>
        /// Snyk service account token (SNYK_TOKEN). Use a group-level service account so a single token
        /// can report scans into any org via --org. Inject from Key Vault; never use a personal token.
        /// </summary>
        public string? Token { get; set; }

        /// <summary>OAuth 2.0 client-credentials service account id (optional hardening over <see cref="Token"/>).</summary>
        public string? OAuthClientId { get; set; }

        /// <summary>OAuth 2.0 client-credentials service account secret.</summary>
        public string? OAuthClientSecret { get; set; }

        /// <summary>
        /// Snyk OAuth 2.0 token endpoint used to exchange the client credentials for a short-lived access
        /// token (RFC 6749 client_credentials grant). Defaults to the US region; override for EU/AU tenants
        /// (e.g. <c>https://api.eu.snyk.io/oauth2/token</c>).
        /// </summary>
        public string OAuthTokenUrl { get; set; } = "https://api.snyk.io/oauth2/token";

        /// <summary>Default Snyk org id for GitHub orgs without an explicit mapping.</summary>
        public string? DefaultSnykOrgId { get; set; }

        /// <summary>Default gate severity: low | medium | high | critical.</summary>
        public string DefaultSeverityThreshold { get; set; } = "high";

        /// <summary>Default manifest ecosystem: npm | nuget | maven | gradle | pip | go | none.</summary>
        public string DefaultEcosystem { get; set; } = "nuget";

        /// <summary>Timeout for a single Snyk CLI invocation.</summary>
        public int ScanTimeoutSeconds { get; set; } = 600;

        /// <summary>When true, open a bot-authored remediation PR when fixable upgrades are found.</summary>
        public bool OpenFixPullRequests { get; set; } = true;

        /// <summary>
        /// When true, also run <c>snyk monitor</c> after the gating test so the scan is persisted to the
        /// Snyk Web UI and the Check Run can deep-link to the snapshot. Off by default: monitoring creates
        /// a Snyk project per repository (the PR branch is the target reference), a side effect that should
        /// be opted into per deployment. Also drives <c>--report</c> publishing for the Code and IaC scans.
        /// </summary>
        public bool Monitor { get; set; } = false;

        /// <summary>
        /// When true, run <c>snyk code test</c> (SAST) and publish a separate "Code" Check Run. Off by
        /// default: Snyk Code is a separately licensed product, so it must be enabled per deployment. A repo
        /// with no scannable source, or an org without the Code entitlement, skips the check rather than failing.
        /// </summary>
        public bool ScanCode { get; set; } = false;

        /// <summary>
        /// When true, run <c>snyk iac test</c> and publish a separate "IaC" Check Run. Off by default: a repo
        /// with no infrastructure-as-code files skips the check rather than posting an empty one.
        /// </summary>
        public bool ScanIac { get; set; } = false;
    }
}
