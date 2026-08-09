using System.Net;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Snyk.Client;
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
            // A repo can accumulate more than one cli target (sample-repo had two); the branch's
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

        /// <summary>
        /// Serves the happy-path OAuth/targets/projects responses but lets a test inject a failure: an HTTP
        /// status on the project DELETE, an HTTP status on the targets listing, or a transport-level throw on
        /// the DELETE (an <see cref="HttpRequestException"/> standing in for a DNS/connect failure that never
        /// reached Snyk). Confirms a transient failure surfaces while an already-gone (404) resource does not.
        /// </summary>
        private sealed class FailingHandler : HttpMessageHandler
        {
            private readonly HttpStatusCode? _deleteStatus;
            private readonly Exception? _deleteThrow;
            private readonly HttpStatusCode _targetsStatus;
            private readonly HttpStatusCode _oauthStatus;

            public FailingHandler(
                HttpStatusCode? deleteStatus = null,
                Exception? deleteThrow = null,
                HttpStatusCode targetsStatus = HttpStatusCode.OK,
                HttpStatusCode oauthStatus = HttpStatusCode.OK)
            {
                _deleteStatus = deleteStatus;
                _deleteThrow = deleteThrow;
                _targetsStatus = targetsStatus;
                _oauthStatus = oauthStatus;
            }

            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                var uri = request.RequestUri!;

                if (uri.AbsoluteUri.Contains("/oauth2/token"))
                {
                    return Json(_oauthStatus, _oauthStatus == HttpStatusCode.OK
                        ? """{"access_token":"tok-123","expires_in":3600}"""
                        : string.Empty);
                }

                if (request.Method == HttpMethod.Delete)
                {
                    if (_deleteThrow is not null)
                    {
                        throw _deleteThrow;
                    }

                    return Json(_deleteStatus ?? HttpStatusCode.NoContent, string.Empty);
                }

                if (uri.AbsolutePath.EndsWith("/targets", StringComparison.Ordinal))
                {
                    return Json(_targetsStatus, _targetsStatus == HttpStatusCode.OK ? TargetsResponse() : string.Empty);
                }

                if (uri.AbsolutePath.EndsWith("/projects", StringComparison.Ordinal))
                {
                    // The branch-ref listing has one project; the post-delete emptiness check comes back empty.
                    return uri.Query.Contains("target_reference", StringComparison.Ordinal)
                        ? Json(HttpStatusCode.OK, Projects("P1"))
                        : Json(HttpStatusCode.OK, """{"data":[]}""");
                }

                return Json(HttpStatusCode.OK, """{"data":[]}""");
            }

            private static Task<HttpResponseMessage> Json(HttpStatusCode status, string json) =>
                Task.FromResult(new HttpResponseMessage(status)
                {
                    Content = new StringContent(json, Encoding.UTF8, "application/json"),
                });
        }

        private static SnykProjectCleanupService BuildWith(FailingHandler handler)
        {
            var client = SnykApiClientFactory.Create(
                new StubHttpClientFactory(handler),
                new SnykOptions { OAuthClientId = "id", OAuthClientSecret = "secret" });
            return new SnykProjectCleanupService(client, NullLogger<SnykProjectCleanupService>.Instance);
        }

        [Fact]
        public async Task ThrowsWhenAProjectDeleteFailsTransiently()
        {
            // A 5xx on the delete is potentially transient, so it must surface (not be swallowed) so the
            // message transport can redeliver rather than leaving the branch's projects orphaned.
            var service = BuildWith(new FailingHandler(deleteStatus: HttpStatusCode.InternalServerError));

            var ex = await Assert.ThrowsAsync<SnykApiException>(() =>
                service.DeleteBranchProjectsAsync(OrgId, RepoUrl, Branch, CancellationToken.None));

            Assert.Equal(500, ex.StatusCode);
        }

        [Fact]
        public async Task TreatsAnAlreadyGoneProjectAsDeletedWithoutThrowing()
        {
            // A 404 means the project is already gone — the desired end state — so cleanup completes normally
            // and counts it, rather than retrying a delete that can never succeed.
            var service = BuildWith(new FailingHandler(deleteStatus: HttpStatusCode.NotFound));

            var deleted = await service.DeleteBranchProjectsAsync(OrgId, RepoUrl, Branch, CancellationToken.None);

            Assert.Equal(1, deleted);
        }

        [Fact]
        public async Task ThrowsWhenTheSnykApiIsUnreachable()
        {
            // A DNS/connect failure never produces an HTTP status; it throws from the transport and must
            // propagate for redelivery, distinct from an already-gone 404.
            var service = BuildWith(new FailingHandler(deleteThrow: new HttpRequestException("no such host")));

            await Assert.ThrowsAsync<HttpRequestException>(() =>
                service.DeleteBranchProjectsAsync(OrgId, RepoUrl, Branch, CancellationToken.None));
        }

        [Fact]
        public async Task ThrowsWhenTheTargetListingFailsTransiently()
        {
            // A rate-limit on the read path is also retryable; it must not be swallowed as "nothing to clean".
            var service = BuildWith(new FailingHandler(targetsStatus: HttpStatusCode.TooManyRequests));

            var ex = await Assert.ThrowsAsync<SnykApiException>(() =>
                service.DeleteBranchProjectsAsync(OrgId, RepoUrl, Branch, CancellationToken.None));

            Assert.Equal(429, ex.StatusCode);
        }

        [Fact]
        public async Task ReturnsZeroWhenTheOrgIsGone()
        {
            // A 404 on the read path (e.g. the org no longer exists) is a permanent condition, not transient,
            // so it is swallowed rather than retried forever.
            var service = BuildWith(new FailingHandler(targetsStatus: HttpStatusCode.NotFound));

            var deleted = await service.DeleteBranchProjectsAsync(OrgId, RepoUrl, Branch, CancellationToken.None);

            Assert.Equal(0, deleted);
        }

        [Fact]
        public async Task ThrowsWhenTheOAuthTokenExchangeFails()
        {
            // A failed token exchange (as opposed to no credentials being configured) is potentially transient,
            // so it must propagate for redelivery rather than being swallowed as a permanent no-op.
            var service = BuildWith(new FailingHandler(oauthStatus: HttpStatusCode.InternalServerError));

            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                service.DeleteBranchProjectsAsync(OrgId, RepoUrl, Branch, CancellationToken.None));
        }
    }
}
