using SnykGhe.Core.Snyk;

namespace SnykGhe.Core.Tests
{
    public class SnykMonitorResultTests
    {
        [Fact]
        public void FirstUri_SingleProjectObject_ReturnsUri()
        {
            const string json = """
        { "ok": true, "projectName": "Acme.Api", "isMonitored": true, "uri": "https://app.snyk.io/org/acme/project/abc-123/history/snap-1" }
        """;

            Assert.Equal("https://app.snyk.io/org/acme/project/abc-123/history/snap-1", SnykMonitorResult.FirstUri(json));
        }

        [Fact]
        public void FirstUri_AllProjectsArray_ReturnsFirstWithUri()
        {
            const string json = """
        [
          { "ok": true, "projectName": "A", "uri": "https://app.snyk.io/org/acme/project/a-1" },
          { "ok": true, "projectName": "B", "uri": "https://app.snyk.io/org/acme/project/b-2" }
        ]
        """;

            Assert.Equal("https://app.snyk.io/org/acme/project/a-1", SnykMonitorResult.FirstUri(json));
        }

        [Fact]
        public void FirstUri_SkipsEntriesWithoutUri()
        {
            const string json = """
        [
          { "ok": false, "projectName": "A" },
          { "ok": true, "projectName": "B", "uri": "https://app.snyk.io/org/acme/project/b-2" }
        ]
        """;

            Assert.Equal("https://app.snyk.io/org/acme/project/b-2", SnykMonitorResult.FirstUri(json));
        }

        [Fact]
        public void FirstUri_EmptyOrUnparseableOrNoUri_ReturnsNull()
        {
            Assert.Null(SnykMonitorResult.FirstUri(""));
            Assert.Null(SnykMonitorResult.FirstUri("not json"));
            Assert.Null(SnykMonitorResult.FirstUri("""{ "ok": true, "projectName": "A" }"""));
            Assert.Null(SnykMonitorResult.FirstUri("[]"));
        }

        [Fact]
        public void Failures_AllProjectsPartialFailure_ReturnsFailedManifestsWithError()
        {
            // --all-projects: one manifest monitored, one errored. Exit code is non-zero but the error is
            // only in this stdout JSON, not stderr.
            const string json = """
        [
          { "ok": true, "projectName": "A", "uri": "https://app.snyk.io/org/acme/project/a-1", "displayTargetFile": "web/package.json" },
          { "ok": false, "error": "Could not build dependency graph: missing lockfile", "displayTargetFile": "api/package.json" }
        ]
        """;

            var failures = SnykMonitorResult.Failures(json);

            var failure = Assert.Single(failures);
            Assert.Equal("api/package.json", failure.Manifest);
            Assert.Equal("Could not build dependency graph: missing lockfile", failure.Error);
        }

        [Fact]
        public void Failures_ManifestPrefersDisplayTargetFileThenTargetFileThenPath()
        {
            Assert.Equal("d.json", Assert.Single(SnykMonitorResult.Failures(
                """[{ "ok": false, "displayTargetFile": "d.json", "targetFile": "t.json", "path": "p" }]""")).Manifest);
            Assert.Equal("t.json", Assert.Single(SnykMonitorResult.Failures(
                """[{ "ok": false, "targetFile": "t.json", "path": "p" }]""")).Manifest);
            Assert.Equal("p", Assert.Single(SnykMonitorResult.Failures(
                """[{ "ok": false, "path": "p" }]""")).Manifest);
        }

        [Fact]
        public void Failures_SingleObjectFatalError_IsReturned()
        {
            const string json = """{ "ok": false, "error": "Authentication failed", "path": "." }""";

            var failure = Assert.Single(SnykMonitorResult.Failures(json));
            Assert.Equal("Authentication failed", failure.Error);
        }

        [Fact]
        public void Failures_SkipsSuccessesAndMalformedEntriesButKeepsValidFailures()
        {
            // A non-string error object on one entry must not discard a well-formed failure on another.
            const string json = """
        [
          { "ok": true, "projectName": "A", "uri": "https://app.snyk.io/org/acme/project/a-1" },
          { "ok": false, "error": { "code": 500 }, "displayTargetFile": "weird" },
          { "ok": false, "error": "real error", "displayTargetFile": "api/pom.xml" }
        ]
        """;

            var failure = Assert.Single(SnykMonitorResult.Failures(json));
            Assert.Equal("api/pom.xml", failure.Manifest);
            Assert.Equal("real error", failure.Error);
        }

        [Fact]
        public void Failures_EmptyOrNoFailures_ReturnsEmpty()
        {
            Assert.Empty(SnykMonitorResult.Failures(""));
            Assert.Empty(SnykMonitorResult.Failures("not json"));
            Assert.Empty(SnykMonitorResult.Failures("[]"));
            Assert.Empty(SnykMonitorResult.Failures("""[{ "ok": true, "uri": "https://app.snyk.io/x" }]"""));
        }
    }
}
