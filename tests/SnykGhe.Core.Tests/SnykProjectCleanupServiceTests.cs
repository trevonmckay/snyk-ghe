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
        /// project list for the branch, the post-delete emptiness check, the bulk-delete POST, and any
        /// fallback DELETE. The two GET /projects calls are told apart by the presence of the
        /// <c>target_reference</c> filter. Each bulk-delete request echoes the project ids it was sent back
        /// as deleted, and records the ids in <see cref="BulkBatches"/> so a test can assert the payload.
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

            /// <summary>The project ids sent to each bulk-delete request, in call order.</summary>
            public List<IReadOnlyList<string>> BulkBatches { get; } = [];

            protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                Requests.Add(request);
                var uri = request.RequestUri!;

                if (uri.AbsoluteUri.Contains("/oauth2/token"))
                {
                    return Ok("""{"access_token":"tok-123","expires_in":3600}""");
                }

                if (uri.AbsolutePath.EndsWith("/bulk-delete", StringComparison.Ordinal))
                {
                    var ids = await BulkDeleteFixtures.RequestedIds(request, cancellationToken);
                    BulkBatches.Add(ids);
                    return Ok(BulkDeleteFixtures.Summary(deleted: ids));
                }

                if (request.Method == HttpMethod.Delete)
                {
                    return new HttpResponseMessage(HttpStatusCode.NoContent);
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

            private static HttpResponseMessage Ok(string json) =>
                new(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") };
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
            // One bulk request carries both branch projects — no per-project DELETE, no target teardown.
            var batch = Assert.Single(handler.BulkBatches);
            Assert.Equal(new[] { "P1", "P2" }, batch);
            Assert.Empty(Deletes(handler, "/projects/"));
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
            // Each cli target's branch project is torn down by its own bulk request.
            Assert.Equal(2, handler.BulkBatches.Count);

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
            // Snyk's next link preserves the original query, including target_reference, so the continuation
            // is still recognized as the branch-ref listing.
            var page1 = "{\"data\":[{\"id\":\"P1\",\"type\":\"project\"}]," +
                "\"links\":{\"next\":\"/rest/orgs/" + OrgId + "/projects?version=2024-10-15&target_reference=fix%2Fsnyk-open-source-vulns&starting_after=cursor2\"}}";
            var page2 = Projects("P2");
            var (service, handler) = Build(TargetsResponse(), new[] { page1, page2 }, remainingJson: Projects("MAIN"));

            var deleted = await service.DeleteBranchProjectsAsync(OrgId, RepoUrl, Branch, CancellationToken.None);

            Assert.Equal(2, deleted);
            // Both pages are collected before deletion, then removed in a single bulk request.
            var batch = Assert.Single(handler.BulkBatches);
            Assert.Equal(new[] { "P1", "P2" }, batch);
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
        /// Serves the happy-path OAuth/targets/projects responses but lets a test inject a failure on the
        /// delete path: an HTTP status on the bulk-delete POST, a transport-level throw on it (an
        /// <see cref="HttpRequestException"/> standing in for a DNS/connect failure that never reached Snyk),
        /// a bulk response that reports the project as failed or leaves it out of both result lists (Snyk's
        /// answer for a project it does not find), an HTTP status on the single-project DELETE the service
        /// then falls back to, or an HTTP status on the targets listing. Confirms a transient failure surfaces
        /// while an already-gone (404) resource does not.
        /// </summary>
        private sealed class FailingHandler : HttpMessageHandler
        {
            private readonly HttpStatusCode _bulkStatus;
            private readonly Exception? _bulkThrow;
            private readonly string? _bulkFailReason;
            private readonly bool _bulkOmits;
            private readonly bool _bulkNoMeta;
            private readonly HttpStatusCode? _deleteStatus;
            private readonly HttpStatusCode _targetsStatus;
            private readonly HttpStatusCode _oauthStatus;

            public FailingHandler(
                HttpStatusCode bulkStatus = HttpStatusCode.OK,
                Exception? bulkThrow = null,
                string? bulkFailReason = null,
                bool bulkOmits = false,
                bool bulkNoMeta = false,
                HttpStatusCode? deleteStatus = null,
                HttpStatusCode targetsStatus = HttpStatusCode.OK,
                HttpStatusCode oauthStatus = HttpStatusCode.OK)
            {
                _bulkStatus = bulkStatus;
                _bulkThrow = bulkThrow;
                _bulkFailReason = bulkFailReason;
                _bulkOmits = bulkOmits;
                _bulkNoMeta = bulkNoMeta;
                _deleteStatus = deleteStatus;
                _targetsStatus = targetsStatus;
                _oauthStatus = oauthStatus;
            }

            public List<HttpRequestMessage> Requests { get; } = [];

            protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                Requests.Add(request);
                var uri = request.RequestUri!;

                if (uri.AbsoluteUri.Contains("/oauth2/token"))
                {
                    return Json(_oauthStatus, _oauthStatus == HttpStatusCode.OK
                        ? """{"access_token":"tok-123","expires_in":3600}"""
                        : string.Empty);
                }

                if (uri.AbsolutePath.EndsWith("/bulk-delete", StringComparison.Ordinal))
                {
                    if (_bulkThrow is not null)
                    {
                        throw _bulkThrow;
                    }

                    if (_bulkStatus != HttpStatusCode.OK)
                    {
                        return Json(_bulkStatus, string.Empty);
                    }

                    if (_bulkNoMeta)
                    {
                        return Json(HttpStatusCode.OK, """{"jsonapi":{"version":"1.0"}}""");
                    }

                    var ids = await BulkDeleteFixtures.RequestedIds(request, cancellationToken);
                    var summary = _bulkOmits
                        ? BulkDeleteFixtures.Summary()
                        : _bulkFailReason is null
                            ? BulkDeleteFixtures.Summary(deleted: ids)
                            : BulkDeleteFixtures.Summary(failed: ids.Select(id => (id, _bulkFailReason)));
                    return Json(HttpStatusCode.OK, summary);
                }

                if (request.Method == HttpMethod.Delete)
                {
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

            private static HttpResponseMessage Json(HttpStatusCode status, string json) =>
                new(status) { Content = new StringContent(json, Encoding.UTF8, "application/json") };
        }

        private static SnykProjectCleanupService BuildWith(FailingHandler handler)
        {
            var client = SnykApiClientFactory.Create(
                new StubHttpClientFactory(handler),
                new SnykOptions { OAuthClientId = "id", OAuthClientSecret = "secret" });
            return new SnykProjectCleanupService(client, NullLogger<SnykProjectCleanupService>.Instance);
        }

        [Fact]
        public async Task ThrowsWhenTheBulkDeleteFailsTransiently()
        {
            // A 5xx on the bulk delete is potentially transient, so it must surface (not be swallowed) so the
            // message transport can redeliver rather than leaving the branch's projects orphaned.
            var service = BuildWith(new FailingHandler(bulkStatus: HttpStatusCode.InternalServerError));

            var ex = await Assert.ThrowsAsync<SnykApiException>(() =>
                service.DeleteBranchProjectsAsync(OrgId, RepoUrl, Branch, CancellationToken.None));

            Assert.Equal(500, ex.StatusCode);
        }

        [Fact]
        public async Task TreatsAnAlreadyGoneProjectAsDeletedWithoutThrowing()
        {
            // Snyk's bulk delete ignores a project it does not find, leaving it out of both result lists. The
            // service confirms it with the single-project delete, whose 404 means already gone — the desired end
            // state — so cleanup completes normally and counts it, rather than retrying a delete that can never
            // succeed.
            var service = BuildWith(new FailingHandler(bulkOmits: true, deleteStatus: HttpStatusCode.NotFound));

            var deleted = await service.DeleteBranchProjectsAsync(OrgId, RepoUrl, Branch, CancellationToken.None);

            Assert.Equal(1, deleted);
        }

        [Fact]
        public async Task DeletesAProjectTheBulkResponseLeftUnaccountedFor()
        {
            // A project missing from both result lists is not trusted to be gone: it goes through the
            // single-project delete, so one Snyk failed to resolve is still removed rather than orphaned.
            var handler = new FailingHandler(bulkOmits: true);
            var service = BuildWith(handler);

            var deleted = await service.DeleteBranchProjectsAsync(OrgId, RepoUrl, Branch, CancellationToken.None);

            Assert.Equal(1, deleted);
            Assert.Contains(handler.Requests, r =>
                r.Method == HttpMethod.Delete && r.RequestUri!.AbsolutePath.EndsWith("/projects/P1", StringComparison.Ordinal));
        }

        [Fact]
        public async Task DeletesIndividuallyWhenTheBulkResponseHasNoMetaSummary()
        {
            // A success response without the result summary may follow a delete Snyk already performed. Throwing
            // would redeliver into a listing that no longer finds the projects, skipping the target teardown, so
            // each project is instead confirmed through the single-project delete.
            var handler = new FailingHandler(bulkNoMeta: true);
            var service = BuildWith(handler);

            var deleted = await service.DeleteBranchProjectsAsync(OrgId, RepoUrl, Branch, CancellationToken.None);

            Assert.Equal(1, deleted);
            Assert.Contains(handler.Requests, r =>
                r.Method == HttpMethod.Delete && r.RequestUri!.AbsolutePath.EndsWith("/projects/P1", StringComparison.Ordinal));
        }

        [Fact]
        public async Task FallsBackToIndividualDeletesWhenBulkDeleteIsUnavailable()
        {
            // The org was just resolved by the target lookup, so a 404 from the bulk endpoint means it is not
            // served (an API version that predates it, or a region without it) — not that the projects are gone.
            // Cleanup must still delete them rather than completing as a no-op.
            var handler = new FailingHandler(bulkStatus: HttpStatusCode.NotFound);
            var service = BuildWith(handler);

            var deleted = await service.DeleteBranchProjectsAsync(OrgId, RepoUrl, Branch, CancellationToken.None);

            Assert.Equal(1, deleted);
            Assert.Contains(handler.Requests, r =>
                r.Method == HttpMethod.Delete && r.RequestUri!.AbsolutePath.EndsWith("/projects/P1", StringComparison.Ordinal));
        }

        [Fact]
        public async Task ThrowsWhenTheFallbackDeleteFailsTransiently()
        {
            // A project the bulk endpoint reports as failed is retried with a single DELETE; a 5xx there is
            // transient and must surface so the message redelivers, not be swallowed.
            var service = BuildWith(new FailingHandler(
                bulkFailReason: "delete_failed", deleteStatus: HttpStatusCode.InternalServerError));

            var ex = await Assert.ThrowsAsync<SnykApiException>(() =>
                service.DeleteBranchProjectsAsync(OrgId, RepoUrl, Branch, CancellationToken.None));

            Assert.Equal(500, ex.StatusCode);
        }

        [Fact]
        public async Task ThrowsWhenTheSnykApiIsUnreachable()
        {
            // A DNS/connect failure never produces an HTTP status; it throws from the transport and must
            // propagate for redelivery, distinct from an already-gone 404.
            var service = BuildWith(new FailingHandler(bulkThrow: new HttpRequestException("no such host")));

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
