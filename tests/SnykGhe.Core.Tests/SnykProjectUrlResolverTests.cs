using System.Net;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SnykGhe.Core.Configuration;
using SnykGhe.Core.Snyk;

namespace SnykGhe.Core.Tests
{
    public class SnykProjectUrlResolverTests
    {
        private const string OrgId = "11111111-2222-3333-4444-555555555555";
        private const string ProjectId = "db66cddb-f0f3-4c89-bc7e-92f367b2dd70";

        /// <summary>
        /// Routes by request URL so a single handler can serve the OAuth token exchange, the projects
        /// list, and the org lookup that one ResolveAsync call makes.
        /// </summary>
        private sealed class RoutingHandler : HttpMessageHandler
        {
            private readonly string _projectsJson;
            private readonly string _orgJson;

            public RoutingHandler(string projectsJson, string orgJson)
            {
                _projectsJson = projectsJson;
                _orgJson = orgJson;
            }

            public List<HttpRequestMessage> Requests { get; } = [];
            public int OrgCalls { get; private set; }

            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                Requests.Add(request);
                var path = request.RequestUri!.AbsolutePath;
                var json = request.RequestUri.AbsoluteUri switch
                {
                    var u when u.Contains("/oauth2/token") => """{"access_token":"tok-123","expires_in":3600}""",
                    var u when u.Contains("/projects") => _projectsJson,
                    _ => _orgJson,
                };

                if (path.EndsWith($"/orgs/{OrgId}", StringComparison.Ordinal))
                {
                    OrgCalls++;
                }

                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(json, Encoding.UTF8, "application/json"),
                });
            }
        }

        private sealed class StubHttpClientFactory : IHttpClientFactory
        {
            private readonly HttpMessageHandler _handler;

            public StubHttpClientFactory(HttpMessageHandler handler)
            {
                _handler = handler;
            }

            public HttpClient CreateClient(string name) => new(_handler, disposeHandler: false);
        }

        private static string ProjectsResponse(string id) =>
            """{"data":[{"id":"__ID__","type":"project","attributes":{"name":"acme/widget","type":"sast"}}]}"""
                .Replace("__ID__", id);

        private const string OrgResponse =
            """{"data":{"id":"org","type":"org","attributes":{"name":"Acme","slug":"acme-group"}}}""";

        private static (SnykProjectUrlResolver Resolver, RoutingHandler Handler) Build(
            string projectsJson,
            string orgJson,
            SnykOptions? options = null)
        {
            var handler = new RoutingHandler(projectsJson, orgJson);
            var factory = new StubHttpClientFactory(handler);
            var opts = options ?? new SnykOptions { OAuthClientId = "id", OAuthClientSecret = "secret" };

            var client = SnykApiClientFactory.Create(factory, opts);
            var resolver = new SnykProjectUrlResolver(client, Options.Create(opts), NullLogger<SnykProjectUrlResolver>.Instance);
            return (resolver, handler);
        }

        private static ResolvedPolicy Policy(string? orgId = OrgId) => new()
        {
            GitHubOrg = "acme",
            SnykOrgId = orgId,
            SeverityThreshold = "high",
            Ecosystem = "nuget",
        };

        [Fact]
        public async Task ResolveAsync_BuildsWebUiUrlFromSlugAndProjectId()
        {
            var (resolver, handler) = Build(ProjectsResponse(ProjectId), OrgResponse);

            var url = await resolver.ResolveAsync(SnykProduct.Code, "acme/widget", "feature/x", Policy(), CancellationToken.None);

            Assert.Equal($"https://app.snyk.io/org/acme-group/project/{ProjectId}", url);

            var projectsRequest = handler.Requests.Single(r => r.RequestUri!.AbsoluteUri.Contains("/projects"));
            var query = projectsRequest.RequestUri!.Query;
            Assert.Contains("types=sast", query);
            Assert.Contains("names=acme%2Fwidget", query);
            Assert.Contains("target_reference=feature%2Fx", query);
            Assert.Contains($"version={new SnykOptions().RestApiVersion}", query);
            Assert.Equal("Bearer", projectsRequest.Headers.Authorization!.Scheme);
            Assert.Equal("tok-123", projectsRequest.Headers.Authorization.Parameter);
        }

        [Fact]
        public async Task ResolveAsync_HonoursRegionalBaseUrls()
        {
            var options = new SnykOptions
            {
                OAuthClientId = "id",
                OAuthClientSecret = "secret",
                ApiBaseUrl = "https://api.eu.snyk.io",
                WebAppBaseUrl = "https://app.eu.snyk.io",
            };
            var (resolver, handler) = Build(ProjectsResponse(ProjectId), OrgResponse, options);

            var url = await resolver.ResolveAsync(SnykProduct.Code, "acme/widget", "main", Policy(), CancellationToken.None);

            Assert.Equal($"https://app.eu.snyk.io/org/acme-group/project/{ProjectId}", url);
            Assert.All(handler.Requests.Where(r => r.RequestUri!.AbsoluteUri.Contains("/rest/")),
                r => Assert.StartsWith("https://api.eu.snyk.io/", r.RequestUri!.AbsoluteUri));
        }

        [Fact]
        public async Task ResolveAsync_ReturnsNull_WhenProjectNotFound()
        {
            var (resolver, _) = Build("""{"data":[]}""", OrgResponse);

            var url = await resolver.ResolveAsync(SnykProduct.Code, "acme/widget", "main", Policy(), CancellationToken.None);

            Assert.Null(url);
        }

        [Fact]
        public async Task ResolveAsync_ReturnsNull_WhenNoSnykOrgMapped()
        {
            var (resolver, handler) = Build(ProjectsResponse(ProjectId), OrgResponse);

            var url = await resolver.ResolveAsync(SnykProduct.Code, "acme/widget", "main", Policy(orgId: null), CancellationToken.None);

            Assert.Null(url);
            Assert.Empty(handler.Requests);
        }

        [Fact]
        public async Task ResolveAsync_ReturnsNull_WhenOAuthNotConfigured()
        {
            var (resolver, handler) = Build(ProjectsResponse(ProjectId), OrgResponse, new SnykOptions());

            var url = await resolver.ResolveAsync(SnykProduct.Code, "acme/widget", "main", Policy(), CancellationToken.None);

            Assert.Null(url);
            Assert.Empty(handler.Requests);
        }

        [Fact]
        public async Task ResolveAsync_ReturnsNull_ForUnmappedProduct()
        {
            var (resolver, handler) = Build(ProjectsResponse(ProjectId), OrgResponse);

            var url = await resolver.ResolveAsync(SnykProduct.Iac, "acme/widget", "main", Policy(), CancellationToken.None);

            Assert.Null(url);
            Assert.Empty(handler.Requests);
        }

        [Fact]
        public async Task ResolveAsync_CachesOrgSlugAcrossCalls()
        {
            var (resolver, handler) = Build(ProjectsResponse(ProjectId), OrgResponse);

            await resolver.ResolveAsync(SnykProduct.Code, "acme/widget", "main", Policy(), CancellationToken.None);
            await resolver.ResolveAsync(SnykProduct.Code, "acme/widget", "main", Policy(), CancellationToken.None);

            Assert.Equal(1, handler.OrgCalls);
        }
    }
}
