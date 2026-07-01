using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SnykGhe.Core.Configuration;

namespace SnykGhe.Core.Snyk
{
    /// <summary>
    /// Removes the Snyk projects a merged/closed PR left behind. Each PR scan runs <c>snyk monitor</c> with
    /// <c>--target-reference=&lt;branch&gt;</c>, which publishes a branch reference under the repository's Snyk
    /// target; once GitHub deletes the branch, that reference is orphaned. This deletes the projects for a
    /// single branch reference (scoped to the repository's target so a same-named branch in another repo is
    /// untouched), and removes the target itself if that reference was its last. Best-effort: every failure
    /// (no org mapping, no OAuth, target/project not found, any API error) is logged and swallowed.
    /// </summary>
    public sealed class SnykProjectCleanupService
    {
        // Shares the REST client SnykProjectUrlResolver registers, so it inherits the same base address and policies.
        public const string HttpClientName = SnykProjectUrlResolver.HttpClientName;

        // Snyk REST API is JSON:API; requests and responses use the vnd.api+json media type.
        private const string JsonApiMediaType = "application/vnd.api+json";

        private readonly IHttpClientFactory _httpClientFactory;
        private readonly SnykOAuthTokenProvider _oauthTokenProvider;
        private readonly SnykOptions _options;
        private readonly ILogger<SnykProjectCleanupService> _logger;

        public SnykProjectCleanupService(
            IHttpClientFactory httpClientFactory,
            SnykOAuthTokenProvider oauthTokenProvider,
            IOptions<SnykOptions> options,
            ILogger<SnykProjectCleanupService> logger)
        {
            _httpClientFactory = httpClientFactory;
            _oauthTokenProvider = oauthTokenProvider;
            _options = options.Value;
            _logger = logger;
        }

        /// <summary>
        /// Deletes every Snyk project whose target reference is <paramref name="branchReference"/> under the
        /// target matching <paramref name="remoteRepoUrl"/>, then removes the target if it has no projects left.
        /// Returns the number of projects deleted (0 when nothing matched or cleanup is not configured).
        /// </summary>
        public async Task<int> DeleteBranchProjectsAsync(
            string? snykOrgId,
            string remoteRepoUrl,
            string branchReference,
            CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(snykOrgId) || !_oauthTokenProvider.IsConfigured || string.IsNullOrWhiteSpace(branchReference))
            {
                return 0;
            }

            try
            {
                var token = await _oauthTokenProvider.GetAccessTokenAsync(cancellationToken);

                var targetId = await FindTargetIdAsync(snykOrgId!, remoteRepoUrl, token, cancellationToken);
                if (targetId is null)
                {
                    _logger.LogInformation("No Snyk target for {Repo}; nothing to clean up for branch {Ref}.", remoteRepoUrl, branchReference);
                    return 0;
                }

                var projectIds = await ListProjectIdsAsync(snykOrgId!, targetId, branchReference, token, cancellationToken);
                if (projectIds.Count == 0)
                {
                    _logger.LogInformation("No Snyk projects for branch {Ref} on {Repo}; nothing to delete.", branchReference, remoteRepoUrl);
                    return 0;
                }

                var deleted = 0;
                foreach (var projectId in projectIds)
                {
                    if (await DeleteProjectAsync(snykOrgId!, projectId, token, cancellationToken))
                    {
                        deleted++;
                    }
                }

                _logger.LogInformation("Deleted {Count} Snyk project(s) for branch {Ref} on {Repo}.", deleted, branchReference, remoteRepoUrl);

                // If that was the target's last reference, the target is now an empty shell — remove it too.
                // When default-branch monitoring is enabled the target keeps its default-branch reference, so
                // this teardown does not fire for an actively-monitored repo — deleting a feature branch leaves
                // the durable default-branch snapshot intact, which is the intended behavior.
                if (deleted > 0 && !await TargetHasProjectsAsync(snykOrgId!, targetId, token, cancellationToken))
                {
                    if (await DeleteTargetAsync(snykOrgId!, targetId, token, cancellationToken))
                    {
                        _logger.LogInformation("Removed empty Snyk target for {Repo} after deleting its last branch reference.", remoteRepoUrl);
                    }
                }

                return deleted;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Snyk cleanup for branch {Ref} on {Repo} did not complete.", branchReference, remoteRepoUrl);
                return 0;
            }
        }

        private async Task<string?> FindTargetIdAsync(string orgId, string remoteRepoUrl, string token, CancellationToken cancellationToken)
        {
            var url = $"{ApiBase}/rest/orgs/{Uri.EscapeDataString(orgId)}/targets?" +
                $"version={Uri.EscapeDataString(_options.RestApiVersion)}" +
                $"&url={Uri.EscapeDataString(remoteRepoUrl)}" +
                "&limit=10";

            using var doc = await GetJsonAsync(url, token, cancellationToken);
            if (doc is null || !doc.RootElement.TryGetProperty("data", out var data) || data.ValueKind != JsonValueKind.Array)
            {
                return null;
            }

            string? firstId = null;
            foreach (var item in data.EnumerateArray())
            {
                if (!item.TryGetProperty("id", out var id) || id.ValueKind != JsonValueKind.String)
                {
                    continue;
                }

                var idStr = id.GetString();
                firstId ??= idStr;

                // The server-side url filter is a match, not necessarily exact; prefer the target whose url is
                // identical so a longer repo path that shares this prefix cannot be cleaned up by mistake.
                if (item.TryGetProperty("attributes", out var attributes)
                    && attributes.TryGetProperty("url", out var urlAttr)
                    && urlAttr.ValueKind == JsonValueKind.String
                    && string.Equals(urlAttr.GetString(), remoteRepoUrl, StringComparison.OrdinalIgnoreCase))
                {
                    return idStr;
                }
            }

            return firstId;
        }

        private async Task<List<string>> ListProjectIdsAsync(string orgId, string targetId, string branchReference, string token, CancellationToken cancellationToken)
        {
            var ids = new List<string>();

            string? url = $"{ApiBase}/rest/orgs/{Uri.EscapeDataString(orgId)}/projects?" +
                $"version={Uri.EscapeDataString(_options.RestApiVersion)}" +
                $"&target_id={Uri.EscapeDataString(targetId)}" +
                $"&target_reference={Uri.EscapeDataString(branchReference)}" +
                "&limit=100";

            while (url is not null)
            {
                using var doc = await GetJsonAsync(url, token, cancellationToken);
                if (doc is null)
                {
                    break;
                }

                var root = doc.RootElement;
                if (root.TryGetProperty("data", out var data) && data.ValueKind == JsonValueKind.Array)
                {
                    foreach (var item in data.EnumerateArray())
                    {
                        if (item.TryGetProperty("id", out var id) && id.ValueKind == JsonValueKind.String)
                        {
                            var idStr = id.GetString();
                            if (!string.IsNullOrEmpty(idStr))
                            {
                                ids.Add(idStr);
                            }
                        }
                    }
                }

                url = NextLink(root);
            }

            return ids;
        }

        private async Task<bool> TargetHasProjectsAsync(string orgId, string targetId, string token, CancellationToken cancellationToken)
        {
            var url = $"{ApiBase}/rest/orgs/{Uri.EscapeDataString(orgId)}/projects?" +
                $"version={Uri.EscapeDataString(_options.RestApiVersion)}" +
                $"&target_id={Uri.EscapeDataString(targetId)}" +
                "&limit=1";

            using var doc = await GetJsonAsync(url, token, cancellationToken);
            return doc is not null
                && doc.RootElement.TryGetProperty("data", out var data)
                && data.ValueKind == JsonValueKind.Array
                && data.GetArrayLength() > 0;
        }

        private Task<bool> DeleteProjectAsync(string orgId, string projectId, string token, CancellationToken cancellationToken)
        {
            var url = $"{ApiBase}/rest/orgs/{Uri.EscapeDataString(orgId)}/projects/{Uri.EscapeDataString(projectId)}" +
                $"?version={Uri.EscapeDataString(_options.RestApiVersion)}";
            return SendDeleteAsync(url, token, cancellationToken);
        }

        private Task<bool> DeleteTargetAsync(string orgId, string targetId, string token, CancellationToken cancellationToken)
        {
            var url = $"{ApiBase}/rest/orgs/{Uri.EscapeDataString(orgId)}/targets/{Uri.EscapeDataString(targetId)}" +
                $"?version={Uri.EscapeDataString(_options.RestApiVersion)}";
            return SendDeleteAsync(url, token, cancellationToken);
        }

        // Snyk paginates JSON:API collections with a cursor carried in links.next, which is a root-relative
        // path (occasionally an object with an href). A missing/blank next link terminates the walk.
        private string? NextLink(JsonElement root)
        {
            if (!root.TryGetProperty("links", out var links) || links.ValueKind != JsonValueKind.Object
                || !links.TryGetProperty("next", out var next))
            {
                return null;
            }

            var href = next.ValueKind switch
            {
                JsonValueKind.String => next.GetString(),
                JsonValueKind.Object when next.TryGetProperty("href", out var h) && h.ValueKind == JsonValueKind.String => h.GetString(),
                _ => null,
            };

            if (string.IsNullOrWhiteSpace(href))
            {
                return null;
            }

            if (href.StartsWith("http", StringComparison.OrdinalIgnoreCase))
            {
                return href;
            }

            return href.StartsWith('/') ? $"{ApiBase}{href}" : $"{ApiBase}/{href}";
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

        private async Task<bool> SendDeleteAsync(string url, string token, CancellationToken cancellationToken)
        {
            using var request = new HttpRequestMessage(HttpMethod.Delete, url);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(JsonApiMediaType));

            var http = _httpClientFactory.CreateClient(HttpClientName);
            using var response = await http.SendAsync(request, cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                var body = await response.Content.ReadAsStringAsync(cancellationToken);
                _logger.LogWarning("Snyk REST DELETE {Url} failed ({Status}): {Body}", url, (int)response.StatusCode, body.Trim());
                return false;
            }

            return true;
        }

        private string ApiBase => _options.ApiBaseUrl.TrimEnd('/');
    }
}
