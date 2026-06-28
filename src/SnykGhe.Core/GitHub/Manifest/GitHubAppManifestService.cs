using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.Extensions.Options;
using SnykGhe.Core.Configuration;

namespace SnykGhe.Core.GitHub.Manifest
{
    /// <summary>
    /// Builds the GitHub App manifest from <see cref="GitHubAppDefinition"/> and exchanges the temporary
    /// code GitHub returns after App creation for the App's credentials. The conversion endpoint is
    /// unauthenticated (the one-time code is the credential), so a plain HTTP client is used.
    /// </summary>
    public sealed class GitHubAppManifestService
    {
        private readonly HttpClient _http;
        private readonly GitHubOptions _gitHub;

        public GitHubAppManifestService(HttpClient http, IOptions<GitHubOptions> gitHub)
        {
            _http = http;
            _gitHub = gitHub.Value;
        }

        /// <summary>
        /// The GitHub web host that serves the App-creation page, derived from the API base URL. For
        /// <c>ghe.com</c> the API host is <c>api.SUBDOMAIN.ghe.com</c> and the web host drops the
        /// <c>api.</c> label.
        /// </summary>
        public string WebBaseUrl
        {
            get
            {
                if (string.IsNullOrWhiteSpace(_gitHub.ApiBaseUrl))
                {
                    throw new InvalidOperationException(
                        "GitHub:ApiBaseUrl is not configured; cannot derive the App-creation URL.");
                }

                var uri = new Uri(_gitHub.ApiBaseUrl);
                var host = uri.Host;
                if (host.StartsWith("api.", StringComparison.OrdinalIgnoreCase))
                {
                    host = host.Substring("api.".Length);
                }

                return $"{uri.Scheme}://{host}";
            }
        }

        /// <summary>The URL the manifest form posts to: user-owned, or org-owned when <paramref name="org"/> is set.</summary>
        public Uri NewAppUrl(string? org, string state)
        {
            var encodedState = Uri.EscapeDataString(state);
            return string.IsNullOrWhiteSpace(org)
                ? new Uri($"{WebBaseUrl}/settings/apps/new?state={encodedState}")
                : new Uri($"{WebBaseUrl}/organizations/{Uri.EscapeDataString(org)}/settings/apps/new?state={encodedState}");
        }

        public GitHubAppManifest BuildManifest(string appName, string publicBaseUrl)
        {
            var baseUrl = publicBaseUrl.TrimEnd('/');
            return new GitHubAppManifest
            {
                Name = appName,
                Url = baseUrl,
                Description = "Posts Snyk security results (PR checks, comments, fix PRs) under a bot identity.",
                HookAttributes = new GitHubAppHookAttributes { Url = $"{baseUrl}/api/github/webhooks", Active = true },
                RedirectUrl = $"{baseUrl}/api/github/app/created",
                SetupUrl = $"{baseUrl}/api/github/setup",
                SetupOnUpdate = true,
                Public = false,
                DefaultPermissions = GitHubAppDefinition.Permissions,
                DefaultEvents = GitHubAppDefinition.Events,
            };
        }

        public async Task<ManifestConversionResponse> ConvertCodeAsync(string code, CancellationToken cancellationToken = default)
        {
            var url = $"{_gitHub.ApiBaseUrl!.TrimEnd('/')}/app-manifests/{Uri.EscapeDataString(code)}/conversions";

            using var request = new HttpRequestMessage(HttpMethod.Post, url);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
            request.Headers.UserAgent.Add(new ProductInfoHeaderValue(_gitHub.ProductName, "1.0"));

            using var response = await _http.SendAsync(request, cancellationToken);
            response.EnsureSuccessStatusCode();

            var result = await response.Content.ReadFromJsonAsync<ManifestConversionResponse>(cancellationToken);
            if (result is null || string.IsNullOrEmpty(result.Pem) || result.Id == 0)
            {
                throw new InvalidOperationException("GitHub manifest conversion returned an incomplete response.");
            }

            return result;
        }
    }
}
