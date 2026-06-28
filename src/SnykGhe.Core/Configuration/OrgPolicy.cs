using Microsoft.Extensions.Options;
using SnykGhe.Core.Snyk;
using SnykGhe.Core.Storage;

namespace SnykGhe.Core.Configuration
{
    /// <summary>Effective, fully-resolved policy for a single scan.</summary>
    public sealed class ResolvedPolicy
    {
        public required string GitHubOrg { get; init; }

        public string? SnykOrgId { get; init; }

        public required string SeverityThreshold { get; init; }

        public required string Ecosystem { get; init; }

        public bool Suspended { get; init; }

        public SnykSeverity Threshold => SnykSeverityExtensions.Parse(SeverityThreshold);
    }

    /// <summary>
    /// Resolves the effective policy for a GitHub org from the installation registry, layering any
    /// explicit per-org Snyk mapping and overrides over the global Snyk defaults. Unmapped orgs fall
    /// back to defaults so a freshly-installed org still scans (against the default Snyk org).
    /// </summary>
    public sealed class OrgPolicyResolver
    {
        private readonly IGitHubInstallationRegistry _registry;
        private readonly SnykOptions _defaults;

        public OrgPolicyResolver(IGitHubInstallationRegistry registry, IOptions<SnykOptions> options)
        {
            _registry = registry;
            _defaults = options.Value;
        }

        public async Task<ResolvedPolicy> ResolveAsync(string gitHubOrg, CancellationToken cancellationToken)
        {
            var record = await _registry.FindAsync(gitHubOrg, cancellationToken);

            return new ResolvedPolicy
            {
                GitHubOrg = gitHubOrg,
                SnykOrgId = record?.SnykOrgId ?? _defaults.DefaultSnykOrgId,
                SeverityThreshold = record?.SeverityThreshold ?? _defaults.DefaultSeverityThreshold,
                Ecosystem = record?.Ecosystem ?? _defaults.DefaultEcosystem,
                Suspended = record?.Suspended ?? false,
            };
        }
    }
}
