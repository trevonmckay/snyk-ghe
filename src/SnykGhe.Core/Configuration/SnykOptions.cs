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

        /// <summary>
        /// Base URL of the Snyk REST API, used to resolve a published project's Web UI link. Defaults to the
        /// US region; override for EU/AU tenants (e.g. <c>https://api.eu.snyk.io</c>).
        /// </summary>
        public string ApiBaseUrl { get; set; } = "https://api.snyk.io";

        /// <summary>
        /// Base URL of the Snyk Web UI, used to build the project deep link the Code Check Run points to.
        /// Defaults to the US region; override for EU/AU tenants (e.g. <c>https://app.eu.snyk.io</c>).
        /// </summary>
        public string WebAppBaseUrl { get; set; } = "https://app.snyk.io";

        /// <summary>
        /// Snyk REST API version (date-stamped) sent as the required <c>version</c> query parameter. Pinned so
        /// a server-side default change cannot alter response shapes; bump when adopting a newer GA version.
        /// Must be GA: the Test API is not served on <c>~beta</c> or <c>~experimental</c>, which 404 an
        /// otherwise valid request.
        /// </summary>
        public string RestApiVersion { get; set; } = "2026-03-25";

        /// <summary>
        /// Which engine runs each Snyk product. Cutting a product over to the API is a configuration change;
        /// see <see cref="ScanEngineOptions"/> for the products the API can actually serve.
        /// </summary>
        public ScanEngineOptions Engines { get; set; } = new();

        /// <summary>
        /// Snyk SCM integration id (Settings &gt; Integrations &gt; &lt;your SCM&gt; &gt; Integration ID). Required by the
        /// API-backed Code scan, which reads repository source through the integration rather than from the
        /// checked-out working copy. Unused by the CLI engine.
        /// </summary>
        public string? ScmIntegrationId { get; set; }

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
        /// When true, also run <c>snyk monitor</c> after a pull request's gating test so the PR-branch scan is
        /// persisted to the Snyk Web UI and the Check Run can deep-link to the snapshot. Off by default:
        /// monitoring a PR branch creates a short-lived Snyk project per PR (the PR head branch is the target
        /// reference), a side effect that should be opted into per deployment. Also drives <c>--report</c>
        /// publishing for the Code and IaC scans. This does not govern the default-branch baseline monitor,
        /// which is controlled by <see cref="ScanDefaultBranch"/>.
        /// </summary>
        public bool Monitor { get; set; } = false;

        /// <summary>
        /// When true, run a baseline scan of a repository's default branch on every push to it (typically the
        /// commit a merged PR produces) and <c>snyk monitor</c> the result under the default-branch target
        /// reference. This is the durable monitored snapshot that lets Snyk alert on newly-disclosed
        /// vulnerabilities without a code change — distinct from the opt-in per-PR-branch monitoring in
        /// <see cref="Monitor"/>. On by default; set false to disable the push-triggered baseline entirely.
        /// </summary>
        public bool ScanDefaultBranch { get; set; } = true;

        /// <summary>
        /// When true, coordinate baseline scans through the durable coordination store so a burst of pushes to
        /// one branch collapses to a single in-flight scan (latest commit wins), two workers never scan the same
        /// branch at once, and a commit already scanned (a redelivered message, or a push the in-flight scan's
        /// clone already picked up) is skipped. On by default. Set false to scan every push independently.
        /// </summary>
        public bool CoalesceBaselineScans { get; set; } = true;

        /// <summary>
        /// Lifetime of a baseline-scan single-flight lease. Must comfortably exceed a scan's duration: if a scan
        /// runs longer, another worker may steal the lease and scan the same branch concurrently. A crashed
        /// holder's lease also blocks that branch's baseline scans until this elapses.
        /// </summary>
        public int ScanLeaseMinutes { get; set; } = 30;

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
