using System.Net;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SnykGhe.Core.Configuration;
using SnykGhe.Core.Snyk;

namespace SnykGhe.Core.Tests
{
    public class SnykProjectCleanupServiceTests
    {
        private const string OrgId = "11111111-2222-3333-4444-555555555555";
        private const string TargetId = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        private const string RepoUrl = "https://github.com/acme/widget";
        private const string Branch = "fix/snyk-open-source-vulns";

        // snyk monitor normalizes the CLI target's stored url to the http scheme; the SCM import keeps https.
        private const string CliRepoUrl = "http://github.com/acme/widget";

        /// <summary>
        /// Routes by method + path so one handler can serve the OAuth exchange, the target lookup, the
        /// project list for the branch, the post-delete emptiness check, and the DELETE calls. The two GET
        /// /projects calls are told apart by the presence of the <c>target_reference</c> filter.
        /// </summary>
        private sealed class RoutingHandler : HttpMessageHandler
        {
            private readonly string _targetsJson;
            private readonly Queue<string> _projectsByRef;
            private readonly string _remainingJson;

            public RoutingHandler(string targetsJson, IEnumerable<string> projectsByRef, string remainingJson)
            {
                _targetsJson = targetsJson;
                _projectsByRef = new Queue<string>(projectsByRef);
                _remainingJson = remainingJson;
            }

            public List<HttpRequestMessage> Requests { get; } = [];

            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                Requests.Add(request);
                var uri = request.RequestUri!;

                if (uri.AbsoluteUri.Contains("/oauth2/token"))
                {
                    return Ok("""{"access_token":"tok-123","expires_in":3600}""");
                }

                if (request.Method == HttpMethod.Delete)
                {
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NoContent));
                }

                if (uri.AbsolutePath.EndsWith("/targets", StringComparison.Ordinal))
                {
                    return Ok(_targetsJson);
                }

                if (uri.AbsolutePath.EndsWith("/projects", StringComparison.Ordinal))
                {
                    if (uri.Query.Contains("target_reference", StringComparison.Ordinal))
                    {
                        var json = _projectsByRef.Count > 1 ? _projectsByRef.Dequeue() : _projectsByRef.Peek();
                        return Ok(json);
                    }

                    return Ok(_remainingJson);
                }

                return Ok("""{"data":[]}""");
            }

            private static Task<HttpResponseMessage> Ok(string json) =>
                Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(json, Encoding.UTF8, "application/json"),
                });
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

        private static string Target(string id, string url, string integrationType) =>
            "{\"id\":\"" + id + "\",\"type\":\"target\"," +
            "\"attributes\":{\"url\":\"" + url + "\",\"display_name\":\"acme/widget\"}," +
            "\"relationships\":{\"integration\":{\"data\":{\"id\":\"int-" + id + "\"," +
            "\"attributes\":{\"integration_type\":\"" + integrationType + "\"}}}}}";

        private static string TargetsData(params string[] targets) =>
            "{\"data\":[" + string.Join(",", targets) + "]}";

        // The repository's app-created target: cli origin, http-scheme url (as snyk monitor stores it).
        private static string TargetsResponse() =>
            TargetsData(Target(TargetId, CliRepoUrl, "cli"));

        private static string Projects(params string[] ids) =>
            "{\"data\":[" + string.Join(",", ids.Select(id => $"{{\"id\":\"{id}\",\"type\":\"project\"}}")) + "]}";

        private static (SnykProjectCleanupService Service, RoutingHandler Handler) Build(
            string targetsJson,
            IEnumerable<string> projectsByRef,
            string remainingJson,
            SnykOptions? options = null)
        {
            var handler = new RoutingHandler(targetsJson, projectsByRef, remainingJson);
            var factory = new StubHttpClientFactory(handler);
            var opts = options ?? new SnykOptions { OAuthClientId = "id", OAuthClientSecret = "secret" };

            var client = SnykApiClientFactory.Create(factory, opts);
            var service = new SnykProjectCleanupService(client, NullLogger<SnykProjectCleanupService>.Instance);
            return (service, handler);
        }

        private static IEnumerable<HttpRequestMessage> Deletes(RoutingHandler handler, string pathFragment) =>
            handler.Requests.Where(r => r.Method == HttpMethod.Delete && r.RequestUri!.AbsolutePath.Contains(pathFragment, StringComparison.Ordinal));

        [Fact]
        public async Task DeletesEveryProjectForTheBranchScopedToTheRepoTarget()
        {
            // Target still has another reference after cleanup, so it must not be deleted.
            var (service, handler) = Build(TargetsResponse(), new[] { Projects("P1", "P2") }, remainingJson: Projects("MAIN"));

            var deleted = await service.DeleteBranchProjectsAsync(OrgId, RepoUrl, Branch, CancellationToken.None);

            Assert.Equal(2, deleted);
            Assert.Equal(2, Deletes(handler, "/projects/").Count());
            Assert.Empty(Deletes(handler, "/targets/"));

            var listByRef = handler.Requests.Single(r =>
                r.Method == HttpMethod.Get &&
                r.RequestUri!.AbsolutePath.EndsWith("/projects", StringComparison.Ordinal) &&
                r.RequestUri.Query.Contains("target_reference", StringComparison.Ordinal));
            Assert.Contains($"target_id={TargetId}", listByRef.RequestUri!.Query);
            Assert.Contains("target_reference=fix%2Fsnyk-open-source-vulns", listByRef.RequestUri.Query);
            Assert.Contains($"version={new SnykOptions().RestApiVersion}", listByRef.RequestUri.Query);
            Assert.Equal("Bearer", listByRef.Headers.Authorization!.Scheme);
        }

        [Fact]
        public async Task RemovesTargetWhenItsLastReferenceWasDeleted()
        {
            var (service, handler) = Build(TargetsResponse(), new[] { Projects("P1") }, remainingJson: """{"data":[]}""");

            var deleted = await service.DeleteBranchProjectsAsync(OrgId, RepoUrl, Branch, CancellationToken.None);

            Assert.Equal(1, deleted);
            var targetDelete = Assert.Single(Deletes(handler, "/targets/"));
            Assert.EndsWith($"/targets/{TargetId}", targetDelete.RequestUri!.AbsolutePath);
        }

        [Fact]
        public async Task IgnoresScmTargetAndCleansTheCliTarget()
        {
            // The repo has BOTH an SCM integration target (github-enterprise, https) and the app's own cli
            // target (http). A url lookup finds the SCM one first, but only the cli target's branch references
            // are the app's to delete — the SCM target must never be scanned for deletion.
            var targets = TargetsData(
                Target("scm-1111", RepoUrl, "github-enterprise"),
                Target(TargetId, CliRepoUrl, "cli"));
            var (service, handler) = Build(targets, new[] { Projects("P1", "P2") }, remainingJson: Projects("MAIN"));

            var deleted = await service.DeleteBranchProjectsAsync(OrgId, RepoUrl, Branch, CancellationToken.None);

            Assert.Equal(2, deleted);

            var listByRef = handler.Requests.Single(r =>
                r.Method == HttpMethod.Get &&
                r.RequestUri!.AbsolutePath.EndsWith("/projects", StringComparison.Ordinal) &&
                r.RequestUri.Query.Contains("target_reference", StringComparison.Ordinal));
            Assert.Contains($"target_id={TargetId}", listByRef.RequestUri!.Query);
            Assert.DoesNotContain("scm-1111", listByRef.RequestUri.Query);
        }

        [Fact]
        public async Task CleansEveryCliTargetWhenRepoHasMultiple()
        {
            // A repo can accumulate more than one cli target (atlas-multiplatform had two); the branch's
            // projects may live under either, so every cli target must be cleaned.
            var targets = TargetsData(
                Target("cli-aaaa", CliRepoUrl, "cli"),
                Target("cli-bbbb", CliRepoUrl, "cli"));
            var (service, handler) = Build(targets, new[] { Projects("P1"), Projects("P2") }, remainingJson: Projects("MAIN"));

            var deleted = await service.DeleteBranchProjectsAsync(OrgId, RepoUrl, Branch, CancellationToken.None);

            Assert.Equal(2, deleted);
            Assert.Equal(2, Deletes(handler, "/projects/").Count());

            var refListings = handler.Requests.Where(r =>
                r.Method == HttpMethod.Get &&
                r.RequestUri!.AbsolutePath.EndsWith("/projects", StringComparison.Ordinal) &&
                r.RequestUri.Query.Contains("target_reference", StringComparison.Ordinal)).ToList();
            Assert.Equal(2, refListings.Count);
            Assert.Contains(refListings, r => r.RequestUri!.Query.Contains("target_id=cli-aaaa", StringComparison.Ordinal));
            Assert.Contains(refListings, r => r.RequestUri!.Query.Contains("target_id=cli-bbbb", StringComparison.Ordinal));
        }

        [Fact]
        public async Task FollowsPaginationToCollectEveryProject()
        {
            var page1 = "{\"data\":[{\"id\":\"P1\",\"type\":\"project\"}]," +
                "\"links\":{\"next\":\"/rest/orgs/" + OrgId + "/projects?version=2024-10-15&starting_after=cursor2\"}}";
            var page2 = Projects("P2");
            var (service, handler) = Build(TargetsResponse(), new[] { page1, page2 }, remainingJson: Projects("MAIN"));

            var deleted = await service.DeleteBranchProjectsAsync(OrgId, RepoUrl, Branch, CancellationToken.None);

            Assert.Equal(2, deleted);
            Assert.Equal(2, Deletes(handler, "/projects/").Count());
        }

        [Fact]
        public async Task ReturnsZeroAndDeletesNothingWhenNoTargetMatches()
        {
            var (service, handler) = Build("""{"data":[]}""", new[] { Projects("P1") }, remainingJson: """{"data":[]}""");

            var deleted = await service.DeleteBranchProjectsAsync(OrgId, RepoUrl, Branch, CancellationToken.None);

            Assert.Equal(0, deleted);
            Assert.Empty(Deletes(handler, "/projects/"));
            Assert.Empty(Deletes(handler, "/targets/"));
        }

        [Fact]
        public async Task ReturnsZeroWhenBranchHasNoProjects()
        {
            var (service, handler) = Build(TargetsResponse(), new[] { """{"data":[]}""" }, remainingJson: Projects("MAIN"));

            var deleted = await service.DeleteBranchProjectsAsync(OrgId, RepoUrl, Branch, CancellationToken.None);

            Assert.Equal(0, deleted);
            Assert.Empty(Deletes(handler, "/projects/"));
        }

        [Fact]
        public async Task ReturnsZeroWithoutCallingSnykWhenOAuthNotConfigured()
        {
            var (service, handler) = Build(TargetsResponse(), new[] { Projects("P1") }, remainingJson: """{"data":[]}""", options: new SnykOptions());

            var deleted = await service.DeleteBranchProjectsAsync(OrgId, RepoUrl, Branch, CancellationToken.None);

            Assert.Equal(0, deleted);
            Assert.Empty(handler.Requests);
        }

        [Fact]
        public async Task ReturnsZeroWithoutCallingSnykWhenNoSnykOrgMapped()
        {
            var (service, handler) = Build(TargetsResponse(), new[] { Projects("P1") }, remainingJson: """{"data":[]}""");

            var deleted = await service.DeleteBranchProjectsAsync(snykOrgId: null, RepoUrl, Branch, CancellationToken.None);

            Assert.Equal(0, deleted);
            Assert.Empty(handler.Requests);
        }
    }
}
