using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SnykGhe.Core.Configuration;
using SnykGhe.Core.Snyk;

namespace SnykGhe.Core.Tests
{
    /// <summary>
    /// Guards the Snyk Code API scan's request shape. Snyk runs SAST over an SCM repository as a stateless
    /// flow: asking it to publish errors the whole test, so the scanner must never request publishing even
    /// when the caller intends the scan's findings to reach the Snyk Web UI.
    /// </summary>
    public class ApiCodeScannerTests
    {
        private const string OrgId = "833a0d21-bc6a-4e33-8715-a57b976f5629";

        private const string CreateResponse =
            """{"data":{"attributes":{"status":"pending"},"id":"b4105179-f848-4008-b913-669bdaa0d1f3","type":"test_jobs"}}""";

        private const string FinishedTestResponse =
            """
            {"data":{"attributes":{
              "state":{"execution":"finished","errors":[],"warnings":[]},
              "outcome":{"reason":"no_policy_breach","result":"pass"},
              "effective_summary":{"count":0}
            },"id":"dd90e00a-3776-4fae-b999-156736300026","type":"tests"}}
            """;

        private sealed class CapturingHandler : HttpMessageHandler
        {
            public string? PostedBody { get; private set; }

            protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                var uri = request.RequestUri!.AbsoluteUri;

                if (request.Method == HttpMethod.Post && uri.Contains("/tests?"))
                {
                    PostedBody = await request.Content!.ReadAsStringAsync(cancellationToken);
                    return Json(HttpStatusCode.Accepted, CreateResponse);
                }

                if (uri.Contains("/test_jobs/"))
                {
                    var seeOther = new HttpResponseMessage(HttpStatusCode.SeeOther);
                    seeOther.Headers.Location = new Uri($"/rest/orgs/{OrgId}/tests/dd90e00a-3776-4fae-b999-156736300026", UriKind.Relative);
                    return seeOther;
                }

                if (uri.Contains("/findings"))
                {
                    return Json(HttpStatusCode.OK, """{"data":[]}""");
                }

                return Json(HttpStatusCode.OK, FinishedTestResponse);
            }

            private static HttpResponseMessage Json(HttpStatusCode status, string body) =>
                new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
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

        private static ScanContext Context(bool publish) => new()
        {
            WorkingDirectory = @"C:\work\repo",
            Policy = new ResolvedPolicy
            {
                GitHubOrg = "acme",
                SnykOrgId = OrgId,
                SeverityThreshold = "high",
                Ecosystem = "npm",
            },
            RemoteRepoUrl = "https://example.ghe.com/acme/sample-repo",
            TargetReference = "main",
            ProjectName = "acme/sample-repo",
            Publish = publish,
        };

        private static async Task<JsonElement> ScanAndCaptureConfig(bool publish)
        {
            var handler = new CapturingHandler();
            var options = new SnykOptions { Token = "static-key", ScmIntegrationId = "7f44ee57" };
            var client = SnykApiClientFactory.Create(new StubHttpClientFactory(handler), options);
            var scanner = new ApiCodeScanner(client, Options.Create(options), NullLogger<ApiCodeScanner>.Instance);

            await scanner.ScanAsync(Context(publish), CancellationToken.None);

            using var doc = JsonDocument.Parse(handler.PostedBody!);
            return doc.RootElement.GetProperty("data").GetProperty("attributes").GetProperty("config").Clone();
        }

        /// <summary>
        /// `publish_report: true` on a SAST-over-SCM test fails the whole test server-side with SNYK-9999
        /// ("failed to create project ... got [400] status"), so a caller asking to publish must not turn a
        /// working scan into an errored one. Publishing is SnykMonitor's job.
        /// </summary>
        [Fact]
        public async Task ScanAsync_NeverRequestsPublishing_EvenWhenTheContextAsksToPublish()
        {
            var config = await ScanAndCaptureConfig(publish: true);

            Assert.False(config.GetProperty("publish_report").GetBoolean());
        }

        /// <summary>
        /// Snyk rejects target configuration on a git-URL input outright: "Project name configuration or target
        /// configuration is not possible for a git URL input".
        /// </summary>
        [Fact]
        public async Task ScanAsync_SendsNoTargetConfiguration_ForAnScmResource()
        {
            var config = await ScanAndCaptureConfig(publish: true);

            Assert.False(config.TryGetProperty("target_name", out _));
            Assert.False(config.TryGetProperty("target_reference", out _));
        }

        [Fact]
        public async Task ScanAsync_RequestsOnlyTheSastScanner()
        {
            var config = await ScanAndCaptureConfig(publish: false);

            var scanners = config.GetProperty("scan_config").EnumerateObject().Select(p => p.Name).ToList();
            Assert.Equal(["sast"], scanners);
        }
    }
}
