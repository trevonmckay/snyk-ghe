using System.Collections.Concurrent;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SnykGhe.Core.Configuration;

namespace SnykGhe.Core.Snyk
{
    /// <summary>
    /// Resolves a published Snyk project's Web UI link via the Snyk REST API. Unlike <c>snyk monitor</c>
    /// (whose <c>--json</c> output carries a snapshot <c>uri</c>), <c>snyk code test --report --json</c>
    /// emits only SARIF — the report URL the CLI computes is dropped in JSON mode — so the Code Check Run has
    /// no deep link without this lookup. Best-effort: every failure (no org mapping, no OAuth, project not yet
    /// queryable, any API error) yields null and the summary row falls back to a plain issue count.
    /// </summary>
    public sealed class SnykProjectUrlResolver
    {
        public const string HttpClientName = "snyk-rest";

        // Snyk REST API is JSON:API; requests and responses use the vnd.api+json media type.
        private const string JsonApiMediaType = "application/vnd.api+json";

        private readonly IHttpClientFactory _httpClientFactory;
        private readonly SnykOAuthTokenProvider _oauthTokenProvider;
        private readonly SnykOptions _options;
        private readonly ILogger<SnykProjectUrlResolver> _logger;

        // Org slug is stable for an org id; cache it so only the first lookup per org pays the extra call.
        private readonly ConcurrentDictionary<string, string> _orgSlugCache;

        public SnykProjectUrlResolver(
            IHttpClientFactory httpClientFactory,
            SnykOAuthTokenProvider oauthTokenProvider,
            IOptions<SnykOptions> options,
            ILogger<SnykProjectUrlResolver> logger)
        {
            _httpClientFactory = httpClientFactory;
            _oauthTokenProvider = oauthTokenProvider;
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
            if (string.IsNullOrWhiteSpace(policy.SnykOrgId) || !_oauthTokenProvider.IsConfigured)
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
                var token = await _oauthTokenProvider.GetAccessTokenAsync(cancellationToken);

                var projectId = await FindProjectIdAsync(policy.SnykOrgId!, projectName, targetReference, projectType, token, cancellationToken);
                if (projectId is null)
                {
                    _logger.LogInformation("No Snyk {Type} project found for {Project} ({Ref}); check will have no Snyk link.",
                        projectType, projectName, targetReference);
                    return null;
                }

                var slug = await GetOrgSlugAsync(policy.SnykOrgId!, token, cancellationToken);
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

        private async Task<string?> FindProjectIdAsync(
            string orgId,
            string projectName,
            string targetReference,
            string projectType,
            string token,
            CancellationToken cancellationToken)
        {
            // Filter by type as well as name: the Open Source `snyk monitor` publishes a project with the same
            // owner/repo name, so name alone would be ambiguous.
            var query = $"version={Uri.EscapeDataString(_options.RestApiVersion)}" +
                $"&names={Uri.EscapeDataString(projectName)}" +
                $"&types={Uri.EscapeDataString(projectType)}" +
                "&limit=10";

            if (!string.IsNullOrWhiteSpace(targetReference))
            {
                query += $"&target_reference={Uri.EscapeDataString(targetReference)}";
            }

            var url = $"{ApiBase}/rest/orgs/{Uri.EscapeDataString(orgId)}/projects?{query}";

            using var doc = await GetJsonAsync(url, token, cancellationToken);
            if (doc is null || !doc.RootElement.TryGetProperty("data", out var data) || data.ValueKind != JsonValueKind.Array)
            {
                return null;
            }

            foreach (var item in data.EnumerateArray())
            {
                if (item.TryGetProperty("id", out var id) && id.ValueKind == JsonValueKind.String)
                {
                    return id.GetString();
                }
            }

            return null;
        }

        private async Task<string?> GetOrgSlugAsync(string orgId, string token, CancellationToken cancellationToken)
        {
            if (_orgSlugCache.TryGetValue(orgId, out var cached))
            {
                return cached;
            }

            var url = $"{ApiBase}/rest/orgs/{Uri.EscapeDataString(orgId)}?version={Uri.EscapeDataString(_options.RestApiVersion)}";

            using var doc = await GetJsonAsync(url, token, cancellationToken);
            var slug = doc is not null
                && doc.RootElement.TryGetProperty("data", out var data)
                && data.TryGetProperty("attributes", out var attributes)
                && attributes.TryGetProperty("slug", out var slugElement)
                && slugElement.ValueKind == JsonValueKind.String
                ? slugElement.GetString()
                : null;

            if (!string.IsNullOrWhiteSpace(slug))
            {
                _orgSlugCache[orgId] = slug;
            }

            return slug;
        }

        private async Task<JsonDocument?> GetJsonAsync(string url, string token, CancellationToken cancellationToken)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(JsonApiMediaType));

            var http = _httpClientFactory.CreateClient(HttpClientName);
            using var response = await http.SendAsync(request, cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                var body = await response.Content.ReadAsStringAsync(cancellationToken);
                _logger.LogWarning("Snyk REST call to {Url} failed ({Status}): {Body}", url, (int)response.StatusCode, body.Trim());
                return null;
            }

            var json = await response.Content.ReadAsStringAsync(cancellationToken);
            return string.IsNullOrWhiteSpace(json) ? null : JsonDocument.Parse(json);
        }

        private string ApiBase => _options.ApiBaseUrl.TrimEnd('/');

        // Only Snyk Code is mapped: its project type is the single value `sast`. Snyk IaC uses granular,
        // per-format project types, so it is intentionally left unmapped until those are confirmed.
        private static string? SnykProjectType(SnykProduct product) => product switch
        {
            SnykProduct.Code => "sast",
            _ => null,
        };
    }
}
