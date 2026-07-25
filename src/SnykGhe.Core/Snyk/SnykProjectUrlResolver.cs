using System.Collections.Concurrent;
using Microsoft.Extensions.Options;
using Snyk.Client;
using Snyk.Client.Resources;
using SnykGhe.Core.Configuration;

namespace SnykGhe.Core.Snyk
{
    /// <summary>
    /// Resolves a published Snyk project's Web UI link via the Snyk REST API. Unlike <c>snyk monitor</c>
    /// (whose <c>--json</c> output carries a snapshot <c>uri</c>), <c>snyk code test --report --json</c>
    /// emits only SARIF — the report URL the CLI computes is dropped in JSON mode — so the Code Check Run has
    /// no deep link without this lookup. Best-effort: every failure (no org mapping, no credentials, project
    /// not yet queryable, any API error) yields null and the summary row falls back to a plain issue count.
    /// </summary>
    public sealed class SnykProjectUrlResolver
    {
        private readonly SnykApiClient _client;
        private readonly SnykOptions _options;
        private readonly ILogger<SnykProjectUrlResolver> _logger;

        // Org slug is stable for an org id; cache it so only the first lookup per org pays the extra call.
        private readonly ConcurrentDictionary<string, string> _orgSlugCache;

        public SnykProjectUrlResolver(
            SnykApiClient client,
            IOptions<SnykOptions> options,
            ILogger<SnykProjectUrlResolver> logger)
        {
            _client = client;
            _options = options.Value;
            _logger = logger;
            _orgSlugCache = new ConcurrentDictionary<string, string>();
        }

        /// <summary>
        /// Returns the app.snyk.io project link for the project matching <paramref name="projectName"/>,
        /// <paramref name="targetReference"/> and the product's Snyk type, or null when it cannot be resolved.
        /// The project must already have been published (via <c>--report</c>) before this is called.
        /// </summary>
        public async Task<string?> ResolveAsync(
            SnykProduct product,
            string projectName,
            string targetReference,
            ResolvedPolicy policy,
            CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(policy.SnykOrgId))
            {
                return null;
            }

            var projectType = SnykProjectType(product);
            if (projectType is null)
            {
                return null;
            }

            try
            {
                // Filter by type as well as name: the Open Source `snyk monitor` publishes a project with the
                // same owner/repo name, so name alone would be ambiguous.
                var projects = await _client.Projects.ListAsync(
                    policy.SnykOrgId!,
                    new SnykProjectFilter
                    {
                        Name = projectName,
                        Types = projectType,
                        TargetReference = string.IsNullOrWhiteSpace(targetReference) ? null : targetReference,
                    },
                    cancellationToken);

                var projectId = projects.FirstOrDefault()?.Id;
                if (string.IsNullOrWhiteSpace(projectId))
                {
                    _logger.LogInformation("No Snyk {Type} project found for {Project} ({Ref}); check will have no Snyk link.",
                        projectType, projectName, targetReference);
                    return null;
                }

                var slug = await GetOrgSlugAsync(policy.SnykOrgId!, cancellationToken);
                if (string.IsNullOrWhiteSpace(slug))
                {
                    return null;
                }

                return $"{_options.WebAppBaseUrl.TrimEnd('/')}/org/{slug}/project/{projectId}";
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Could not resolve Snyk {Product} project URL for {Project}; check will have no Snyk link.",
                    product, projectName);
                return null;
            }
        }

        private async Task<string?> GetOrgSlugAsync(string orgId, CancellationToken cancellationToken)
        {
            if (_orgSlugCache.TryGetValue(orgId, out var cached))
            {
                return cached;
            }

            var org = await _client.Orgs.GetAsync(orgId, cancellationToken);
            var slug = org?.Slug;

            if (!string.IsNullOrWhiteSpace(slug))
            {
                _orgSlugCache[orgId] = slug;
            }

            return slug;
        }

        // Only Snyk Code is mapped: its project type is the single value `sast`. Snyk IaC uses granular,
        // per-format project types, so it is intentionally left unmapped until those are confirmed.
        private static string? SnykProjectType(SnykProduct product) => product switch
        {
            SnykProduct.Code => "sast",
            _ => null,
        };
    }
}
