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
    }
}
