using System.Net;
using System.Text;
using SnykGhe.Core.Configuration;
using SnykGhe.Core.Fix;
using SnykGhe.Core.Snyk;
using Snyk.Client;
using Snyk.Client.Tests;
using SnykScannerKind = Snyk.Client.Tests.SnykScanner;

namespace SnykGhe.Core.Tests
{
    /// <summary>
    /// Exercises the Test API client against payloads captured from the live Snyk API, including the
    /// 202 -> poll -> 303 -> findings sequence a real test goes through.
    /// </summary>
    public class SnykTestsApiTests
    {
        private const string OrgId = "833a0d21-bc6a-4e33-8715-a57b976f5629";
        private const string JobId = "b4105179-f848-4008-b913-669bdaa0d1f3";
        private const string TestId = "dd90e00a-3776-4fae-b999-156736300026";

        private const string CreateResponse =
            """{"data":{"attributes":{"created_at":"2026-07-09T17:29:19Z","status":"pending"},"id":"b4105179-f848-4008-b913-669bdaa0d1f3","type":"test_jobs"}}""";

        private const string RunningJobResponse =
            """{"data":{"attributes":{"status":"started"},"id":"b4105179-f848-4008-b913-669bdaa0d1f3","type":"test_jobs"}}""";

        private const string FinishedTestResponse =
            """
            {"data":{"attributes":{
              "state":{"execution":"finished","errors":[],"warnings":[]},
              "outcome":{"reason":"policy_breach","result":"fail"},
              "effective_summary":{"count":1,"count_by":{"severity":{"critical":0,"high":1,"low":0,"medium":0}}}
            },"id":"dd90e00a-3776-4fae-b999-156736300026","type":"tests"}}
            """;

        private const string ErroredTestResponse =
            """
            {"data":{"attributes":{
              "state":{"execution":"errored","errors":{"code":"SNYK-TARGET-0001","detail":"Target not found","status":"500"}},
              "outcome":{}
            },"id":"dd90e00a-3776-4fae-b999-156736300026","type":"tests"}}
            """;

        // Trimmed from a real /findings response for lodash@4.17.15.
        private const string FindingsResponse =
            """
            {"data":[{
              "id":"0b1e3d24-42ef-4365-8889-ce9dab186ce5",
              "type":"findings",
              "attributes":{
                "key":"0b1e3d24-42ef-4365-8889-ce9dab186ce5",
                "title":"Prototype Pollution",
                "finding_type":"sca",
                "rating":{"severity":"high"},
                "evidence":[{"source":"dependency_path","path":[{"name":"myapp","version":"1.0.0"},{"name":"lodash","version":"4.17.15"}]}],
                "locations":[{"type":"package","package":{"name":"lodash","version":"4.17.15"}}],
                "problems":[
                  {"id":"CWE-1321","source":"cwe"},
                  {"id":"SNYK-JS-LODASH-6139239","source":"snyk_vuln","is_fixable":true,"initially_fixed_in_versions":["4.17.17"]}
                ]
              },
              "relationships":{"fix":{"data":{"type":"fixes","attributes":{
                "outcome":"fully_resolved",
                "action":{"format":"upgrade_package_advice","package_name":"lodash","upgrade_paths":[
                  {"is_drop":false,"dependency_path":[{"name":"myapp","version":"1.0.0"},{"name":"lodash","version":"4.17.17"}]}
                ]}
              }}}}
            }]}
            """;

        /// <summary>
        /// Mimics the API's control flow: POST returns a job, the first job poll reports "started", the second
        /// answers 303 to the test resource, and the test and findings are then fetched.
        /// </summary>
        private sealed class TestApiHandler : HttpMessageHandler
        {
            private readonly string _testJson;
            private int _jobPolls;

            public TestApiHandler(string testJson)
            {
                _testJson = testJson;
            }

            public List<HttpRequestMessage> Requests { get; } = [];
            public string? PostedBody { get; private set; }

            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
                HandleAsync(request, cancellationToken);

            public async Task<HttpResponseMessage> HandleAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                Requests.Add(request);
                var uri = request.RequestUri!.AbsoluteUri;

                if (request.Method == HttpMethod.Post && uri.Contains("/tests?"))
                {
                    PostedBody = await request.Content!.ReadAsStringAsync(cancellationToken);
                    return Json(HttpStatusCode.Accepted, CreateResponse);
                }

                if (uri.Contains("/test_jobs/"))
                {
                    if (_jobPolls++ == 0)
                    {
                        return Json(HttpStatusCode.OK, RunningJobResponse);
                    }

                    var seeOther = new HttpResponseMessage(HttpStatusCode.SeeOther);
                    seeOther.Headers.Location = new Uri($"/rest/orgs/{OrgId}/tests/{TestId}?version=2024-10-15", UriKind.Relative);
                    return seeOther;
                }

                if (uri.Contains("/findings"))
                {
                    return Json(HttpStatusCode.OK, FindingsResponse);
                }

                return Json(HttpStatusCode.OK, _testJson);
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

        private static SnykOptions Options() => new() { Token = "static-key" };

        private static SnykTestRequest DepGraphRequest() => new()
        {
            Resources = [new InlineDepGraphResource { Name = "dep_graph.json", DepGraph = System.Text.Json.Nodes.JsonNode.Parse("""{"schemaVersion":"1.3.0"}""")! }],
            Scanners = [SnykScannerKind.Sca],
            Stage = SdlcStage.PrCheck,
            Configuration = new SnykTestConfiguration { PublishReport = false },
        };

        [Fact]
        public async Task RunAsync_PollsJobThenFollowsRedirectAndReadsFindings()
        {
            var handler = new TestApiHandler(FinishedTestResponse);
            var client = SnykApiClientFactory.Create(new StubHttpClientFactory(handler), Options());

            var run = await client.Tests.RunAsync(OrgId, DepGraphRequest(), CancellationToken.None);

            Assert.True(run.Test.Succeeded);
            Assert.Equal("fail", run.Test.Outcome);
            Assert.Equal(1, run.Test.Summary.High);

            var finding = Assert.Single(run.Findings);
            Assert.Equal("Prototype Pollution", finding.Title);
            Assert.Equal("high", finding.Severity);
            Assert.Equal("lodash", finding.Package!.Name);
            Assert.Equal("4.17.15", finding.Package.Version);
            Assert.Equal(["4.17.17"], finding.FixedInVersions);
            Assert.True(finding.Fix!.IsUpgradable);
            Assert.Equal("lodash@4.17.17", finding.Fix.UpgradePath[1].ToString());
        }

        [Fact]
        public async Task CreateAsync_SendsJsonApiMediaTypeAndInlineDepGraphResource()
        {
            var handler = new TestApiHandler(FinishedTestResponse);
            var client = SnykApiClientFactory.Create(new StubHttpClientFactory(handler), Options());

            await client.Tests.CreateAsync(OrgId, DepGraphRequest(), CancellationToken.None);

            var post = handler.Requests.Single(r => r.Method == HttpMethod.Post);
            Assert.Equal("application/vnd.api+json", post.Content!.Headers.ContentType!.MediaType);
            Assert.Contains($"version={new SnykOptions().RestApiVersion}", post.RequestUri!.Query);

            Assert.Contains("\"type\":\"tests\"", handler.PostedBody);
            Assert.Contains("\"sdlc_stage\":\"pr_check\"", handler.PostedBody);
            Assert.Contains("\"type\":\"inline\"", handler.PostedBody);
            Assert.Contains("\"sca\":{}", handler.PostedBody);
            Assert.Contains("\"publish_report\":false", handler.PostedBody);
        }

        /// <summary>
        /// An inline resource may carry provenance for the graph. Snyk omits the key entirely when empty
        /// rather than sending an empty object.
        /// </summary>
        [Fact]
        public async Task InlineDepGraphResource_EmitsScmContext_WhenSupplied()
        {
            var handler = new TestApiHandler(FinishedTestResponse);
            var client = SnykApiClientFactory.Create(new StubHttpClientFactory(handler), Options());

            var request = new SnykTestRequest
            {
                Resources =
                [
                    new InlineDepGraphResource
                    {
                        Name = "package.json",
                        DepGraph = System.Text.Json.Nodes.JsonNode.Parse("""{"schemaVersion":"1.3.0"}""")!,
                        ScmContext = new SnykScmContext
                        {
                            RepositoryUrl = "https://alera-group.ghe.com/Propel/platform-connectivity",
                            Branch = "main",
                        },
                    },
                ],
                Scanners = [SnykScannerKind.Sca],
                Stage = SdlcStage.PrCheck,
            };

            await client.Tests.CreateAsync(OrgId, request, CancellationToken.None);

            Assert.Contains(
                "\"scm_context\":{\"branch\":\"main\",\"repo_url\":\"https://alera-group.ghe.com/Propel/platform-connectivity\"}",
                handler.PostedBody);
        }

        [Fact]
        public async Task InlineDepGraphResource_OmitsScmContext_WhenAbsent()
        {
            var handler = new TestApiHandler(FinishedTestResponse);
            var client = SnykApiClientFactory.Create(new StubHttpClientFactory(handler), Options());

            await client.Tests.CreateAsync(OrgId, DepGraphRequest(), CancellationToken.None);

            Assert.DoesNotContain("scm_context", handler.PostedBody);
        }

        [Fact]
        public async Task StaticApiKey_UsesTokenSchemeNotBearer()
        {
            var handler = new TestApiHandler(FinishedTestResponse);
            var client = SnykApiClientFactory.Create(new StubHttpClientFactory(handler), Options());

            await client.Tests.CreateAsync(OrgId, DepGraphRequest(), CancellationToken.None);

            var post = handler.Requests.Single(r => r.Method == HttpMethod.Post);
            Assert.Equal("Token", post.Headers.Authorization!.Scheme);
            Assert.Equal("static-key", post.Headers.Authorization.Parameter);
        }

        [Fact]
        public async Task OAuthCredentials_UseBearerScheme()
        {
            var handler = new TestApiHandler(FinishedTestResponse);
            var options = new SnykOptions { OAuthClientId = "id", OAuthClientSecret = "secret" };

            // The token exchange goes through the same stub, which answers any non-test URL with the test JSON;
            // route it explicitly by giving the exchange its own handler-backed factory.
            var oauthHandler = new OAuthThenApiHandler(handler);
            var client = SnykApiClientFactory.Create(new StubHttpClientFactory(oauthHandler), options);

            await client.Tests.CreateAsync(OrgId, DepGraphRequest(), CancellationToken.None);

            var post = handler.Requests.Single(r => r.Method == HttpMethod.Post && r.RequestUri!.AbsoluteUri.Contains("/tests?"));
            Assert.Equal("Bearer", post.Headers.Authorization!.Scheme);
            Assert.Equal("tok-abc", post.Headers.Authorization.Parameter);
        }

        /// <summary>Answers the OAuth token exchange, delegating everything else to the API handler.</summary>
        private sealed class OAuthThenApiHandler : HttpMessageHandler
        {
            private readonly TestApiHandler _inner;

            public OAuthThenApiHandler(TestApiHandler inner)
            {
                _inner = inner;
            }

            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                if (request.RequestUri!.AbsoluteUri.Contains("/oauth2/token"))
                {
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent("""{"access_token":"tok-abc","expires_in":3600}""", Encoding.UTF8, "application/json"),
                    });
                }

                return _inner.HandleAsync(request, cancellationToken);
            }
        }

        [Fact]
        public async Task RunAsync_ReturnsErroredTestWithoutFetchingFindings()
        {
            var handler = new TestApiHandler(ErroredTestResponse);
            var client = SnykApiClientFactory.Create(new StubHttpClientFactory(handler), Options());

            var run = await client.Tests.RunAsync(OrgId, DepGraphRequest(), CancellationToken.None);

            Assert.False(run.Test.Succeeded);
            Assert.Empty(run.Findings);
            Assert.Equal("SNYK-TARGET-0001", run.Test.Errors.Single().Code);
            Assert.Contains("Target not found", run.Test.ErrorSummary);
            Assert.DoesNotContain(handler.Requests, r => r.RequestUri!.AbsoluteUri.Contains("/findings"));
        }

        [Fact]
        public async Task MappedFindings_DriveTheFixPlannerLikeCliOutput()
        {
            var handler = new TestApiHandler(FinishedTestResponse);
            var client = SnykApiClientFactory.Create(new StubHttpClientFactory(handler), Options());

            var run = await client.Tests.RunAsync(OrgId, DepGraphRequest(), CancellationToken.None);
            var project = SnykApiFindingMapper.ToProjectResult("package.json", run.Findings);
            var scan = new SnykScanResult { Projects = [project] };

            var plan = new FixPlanner().Plan(scan);

            var upgrade = Assert.Single(plan.Upgrades);
            Assert.Equal("lodash", upgrade.PackageName);
            Assert.Equal("4.17.15", upgrade.FromVersion);
            Assert.Equal("4.17.17", upgrade.ToVersion);
            Assert.Equal(["SNYK-JS-LODASH-6139239"], upgrade.VulnerabilityIds);
        }
    }
}
