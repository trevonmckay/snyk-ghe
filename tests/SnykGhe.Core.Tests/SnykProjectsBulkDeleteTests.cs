using System.Net;
using System.Text;
using System.Text.Json;
using Snyk.Client;
using SnykGhe.Core.Configuration;

namespace SnykGhe.Core.Tests
{
    public class SnykProjectsBulkDeleteTests
    {
        private const string OrgId = "11111111-2222-3333-4444-555555555555";

        /// <summary>Captures every bulk-delete request body and replies with a caller-supplied response.</summary>
        private sealed class BulkDeleteHandler : HttpMessageHandler
        {
            private readonly Func<int, HttpResponseMessage> _respond;

            public BulkDeleteHandler(Func<int, HttpResponseMessage> respond)
            {
                _respond = respond;
            }

            public List<string> Bodies { get; } = [];

            protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                var body = request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync(cancellationToken);
                Bodies.Add(body);
                return _respond(Bodies.Count);
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

        private static SnykApiClient Client(HttpMessageHandler handler) =>
            SnykApiClientFactory.Create(new StubHttpClientFactory(handler), new SnykOptions { Token = "tok-123" });

        private static HttpResponseMessage Json(HttpStatusCode status, string json) =>
            new(status) { Content = new StringContent(json, Encoding.UTF8, "application/vnd.api+json") };

        [Fact]
        public async Task MakesNoRequestForEmptyInputAndReturnsEmptyResult()
        {
            var handler = new BulkDeleteHandler(_ => Json(HttpStatusCode.OK, BulkDeleteFixtures.Summary([])));

            var result = await Client(handler).Projects.BulkDeleteAsync(OrgId, [], CancellationToken.None);

            Assert.Empty(handler.Bodies);
            Assert.Empty(result.Deleted);
            Assert.Empty(result.Failed);
        }

        [Fact]
        public async Task PostsProjectIdsAsJsonApiResourceIdentifiers()
        {
            var handler = new BulkDeleteHandler(_ => Json(HttpStatusCode.OK, BulkDeleteFixtures.Summary(["P1", "P2"])));

            var result = await Client(handler).Projects.BulkDeleteAsync(OrgId, ["P1", "P2"], CancellationToken.None);

            var body = Assert.Single(handler.Bodies);
            using var doc = JsonDocument.Parse(body);
            var data = doc.RootElement.GetProperty("data");
            Assert.Equal(2, data.GetArrayLength());
            Assert.Equal("project", data[0].GetProperty("type").GetString());
            Assert.Equal("P1", data[0].GetProperty("id").GetString());
            Assert.Equal("P2", data[1].GetProperty("id").GetString());

            Assert.Equal(2, result.Deleted.Count);
            Assert.Empty(result.Failed);
        }

        [Fact]
        public async Task HitsTheBulkDeletePathWithTheConfiguredVersion()
        {
            HttpRequestMessage? seen = null;
            var handler = new CapturingHandler(req => seen = req, Json(HttpStatusCode.OK, BulkDeleteFixtures.Summary(["P1"])));

            await Client(handler).Projects.BulkDeleteAsync(OrgId, ["P1"], CancellationToken.None);

            Assert.EndsWith($"/orgs/{OrgId}/projects/bulk-delete", seen!.RequestUri!.AbsolutePath);
            Assert.Equal(HttpMethod.Post, seen.Method);
            Assert.Contains($"version={new SnykOptions().RestApiVersion}", seen.RequestUri.Query);
            Assert.Equal("application/vnd.api+json", seen.Content!.Headers.ContentType!.MediaType);
        }

        [Fact]
        public async Task BatchesIntoRequestsOfAtMostOneHundred()
        {
            var ids = Enumerable.Range(1, 150).Select(i => $"P{i}").ToList();
            var handler = new BulkDeleteHandler(_ => Json(HttpStatusCode.OK, BulkDeleteFixtures.Summary([])));

            await Client(handler).Projects.BulkDeleteAsync(OrgId, ids, CancellationToken.None);

            Assert.Equal(2, handler.Bodies.Count);
            Assert.Equal(100, DataLength(handler.Bodies[0]));
            Assert.Equal(50, DataLength(handler.Bodies[1]));
        }

        [Fact]
        public async Task AggregatesDeletedAndFailedAcrossBatches()
        {
            var ids = Enumerable.Range(1, 150).Select(i => $"P{i}").ToList();
            // First batch: all deleted. Second batch: one reported failed.
            var handler = new BulkDeleteHandler(call => call == 1
                ? Json(HttpStatusCode.OK, BulkDeleteFixtures.Summary(ids.Take(100).ToArray()))
                : Json(HttpStatusCode.OK, BulkDeleteFixtures.Summary(ids.Skip(100).Take(49).ToArray(), [("P150", "delete_failed")])));

            var result = await Client(handler).Projects.BulkDeleteAsync(OrgId, ids, CancellationToken.None);

            Assert.Equal(149, result.Deleted.Count);
            var failure = Assert.Single(result.Failed);
            Assert.Equal("P150", failure.Id);
            Assert.Equal("delete_failed", failure.Reason);
        }

        [Fact]
        public async Task ThrowsWhenTheRequestIsRejected()
        {
            var handler = new BulkDeleteHandler(_ => Json(HttpStatusCode.InternalServerError, string.Empty));

            var ex = await Assert.ThrowsAsync<SnykApiException>(() =>
                Client(handler).Projects.BulkDeleteAsync(OrgId, ["P1"], CancellationToken.None));

            Assert.Equal(500, ex.StatusCode);
        }

        [Fact]
        public async Task ThrowsWhenASuccessResponseHasNoMetaSummary()
        {
            // A 2xx without the required meta summary leaves the batch's outcome unknown; the client must not
            // silently report it as deleting nothing.
            var handler = new BulkDeleteHandler(_ => Json(HttpStatusCode.OK, """{"jsonapi":{"version":"1.0"}}"""));

            await Assert.ThrowsAsync<SnykApiException>(() =>
                Client(handler).Projects.BulkDeleteAsync(OrgId, ["P1"], CancellationToken.None));
        }

        [Fact]
        public async Task SkipsResultEntriesWithoutAnId()
        {
            // An entry that names no project cannot be matched to a requested id, so it is left out rather than
            // surfacing as a project with an empty id.
            const string body = """
                {"jsonapi":{"version":"1.0"},"meta":{
                  "deleted":[{"id":"P1","name":"n-P1"},{"name":"orphan"}],
                  "failed":[{"name":"orphan","reason":"delete_failed"}]}}
                """;
            var handler = new BulkDeleteHandler(_ => Json(HttpStatusCode.OK, body));

            var result = await Client(handler).Projects.BulkDeleteAsync(OrgId, ["P1", "P2"], CancellationToken.None);

            var deleted = Assert.Single(result.Deleted);
            Assert.Equal("P1", deleted.Id);
            Assert.Empty(result.Failed);
        }

        private static int DataLength(string body) => BulkDeleteFixtures.RequestedIds(body).Count;

        private sealed class CapturingHandler : HttpMessageHandler
        {
            private readonly Action<HttpRequestMessage> _capture;
            private readonly HttpResponseMessage _response;

            public CapturingHandler(Action<HttpRequestMessage> capture, HttpResponseMessage response)
            {
                _capture = capture;
                _response = response;
            }

            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                _capture(request);
                return Task.FromResult(_response);
            }
        }
    }
}
