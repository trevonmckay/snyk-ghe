using System.IO.Compression;
using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SnykGhe.Core.Configuration;
using SnykGhe.Core.GitHub;

namespace SnykGhe.Core.Tests
{
    public class CodeScanningSarifUploaderTests
    {
        private const string Sarif = """{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"SnykCode"}},"results":[]}]}""";
        private const string AcceptedBody =
            """{"id":"abc-123","url":"https://api.test.ghe.com/repos/acme/widget/code-scanning/sarifs/abc-123"}""";

        /// <summary>Records each request (and its already-read body) and answers with a fixed status.</summary>
        private sealed class CapturingHandler : HttpMessageHandler
        {
            private readonly HttpStatusCode _status;
            private readonly string _responseBody;

            public CapturingHandler(HttpStatusCode status, string responseBody)
            {
                _status = status;
                _responseBody = responseBody;
            }

            public List<HttpRequestMessage> Requests { get; } = [];
            public List<string> Bodies { get; } = [];

            protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                Requests.Add(request);
                Bodies.Add(request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync(cancellationToken));
                return new HttpResponseMessage(_status)
                {
                    Content = new StringContent(_responseBody, Encoding.UTF8, "application/json"),
                };
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

        private static CodeScanningSarifUploader Build(HttpMessageHandler handler, string? apiBaseUrl = "https://api.test.ghe.com/")
        {
            var factory = new StubHttpClientFactory(handler);
            var options = Options.Create(new GitHubOptions { ApiBaseUrl = apiBaseUrl });
            return new CodeScanningSarifUploader(factory, options, NullLogger<CodeScanningSarifUploader>.Instance);
        }

        private static string Gunzip(string base64)
        {
            var bytes = Convert.FromBase64String(base64);
            using var input = new MemoryStream(bytes);
            using var gzip = new GZipStream(input, CompressionMode.Decompress);
            using var reader = new StreamReader(gzip, Encoding.UTF8);
            return reader.ReadToEnd();
        }

        [Fact]
        public async Task UploadAsync_Posts202_WithGzippedSarifPrRefAndAuth()
        {
            var handler = new CapturingHandler(HttpStatusCode.Accepted, AcceptedBody);
            var uploader = Build(handler);

            await uploader.UploadAsync("acme", "widget", "deadbeef", 42, Sarif, "tok-xyz", CancellationToken.None);

            var request = Assert.Single(handler.Requests);
            Assert.Equal(HttpMethod.Post, request.Method);
            Assert.Equal("https://api.test.ghe.com/repos/acme/widget/code-scanning/sarifs", request.RequestUri!.AbsoluteUri);
            Assert.Equal("Bearer", request.Headers.Authorization!.Scheme);
            Assert.Equal("tok-xyz", request.Headers.Authorization.Parameter);
            Assert.Contains("2022-11-28", request.Headers.GetValues("X-GitHub-Api-Version"));
            Assert.Contains(request.Headers.Accept, a => a.MediaType == "application/vnd.github+json");

            using var doc = JsonDocument.Parse(handler.Bodies[0]);
            Assert.Equal("deadbeef", doc.RootElement.GetProperty("commit_sha").GetString());
            Assert.Equal("refs/pull/42/head", doc.RootElement.GetProperty("ref").GetString());
            Assert.Equal(Sarif, Gunzip(doc.RootElement.GetProperty("sarif").GetString()!));
        }

        [Fact]
        public async Task UploadAsync_403_IsSwallowedAndCachedPerRepo()
        {
            var handler = new CapturingHandler(HttpStatusCode.Forbidden, """{"message":"Advanced Security must be enabled"}""");
            var uploader = Build(handler);

            await uploader.UploadAsync("acme", "widget", "sha", 1, Sarif, "tok", CancellationToken.None);
            await uploader.UploadAsync("acme", "widget", "sha", 2, Sarif, "tok", CancellationToken.None);

            // The second call is skipped: a repo without code scanning is cached as unavailable.
            Assert.Single(handler.Requests);
        }

        [Fact]
        public async Task UploadAsync_413_IsSwallowedButNotCached()
        {
            var handler = new CapturingHandler(HttpStatusCode.RequestEntityTooLarge, "{}");
            var uploader = Build(handler);

            await uploader.UploadAsync("acme", "widget", "sha", 1, Sarif, "tok", CancellationToken.None);
            await uploader.UploadAsync("acme", "widget", "sha", 2, Sarif, "tok", CancellationToken.None);

            // 413 is our-side (oversized payload), not a structural repo limitation — so it must not be cached.
            Assert.Equal(2, handler.Requests.Count);
        }

        [Fact]
        public async Task UploadAsync_NoApiBaseUrl_SkipsWithoutCalling()
        {
            var handler = new CapturingHandler(HttpStatusCode.Accepted, AcceptedBody);
            var uploader = Build(handler, apiBaseUrl: null);

            await uploader.UploadAsync("acme", "widget", "sha", 1, Sarif, "tok", CancellationToken.None);

            Assert.Empty(handler.Requests);
        }
    }
}
