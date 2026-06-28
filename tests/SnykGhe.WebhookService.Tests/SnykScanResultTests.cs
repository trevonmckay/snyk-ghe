using SnykGhe.WebhookService.Snyk;

namespace SnykGhe.WebhookService.Tests
{
    public class SnykScanResultTests
    {
        [Fact]
        public void Parse_SingleProjectObject_ReadsVulnerabilities()
        {
            const string json = """
        {
          "ok": false,
          "projectName": "Acme.Api",
          "vulnerabilities": [
            { "id": "SNYK-1", "title": "RCE", "severity": "critical", "packageName": "Foo", "version": "1.0.0", "isUpgradable": true, "fixedIn": ["1.0.1"] },
            { "id": "SNYK-2", "title": "XSS", "severity": "medium", "packageName": "Bar", "version": "2.0.0" }
          ]
        }
        """;

            var result = SnykScanResult.Parse(json);

            Assert.False(result.Failed);
            Assert.Single(result.Projects);
            Assert.Equal(2, result.AllVulnerabilities.Count());
            Assert.Equal(1, result.CountAtOrAbove(SnykSeverity.High));
            Assert.Equal(2, result.CountAtOrAbove(SnykSeverity.Low));
        }

        [Fact]
        public void Parse_AllProjectsArray_AggregatesAcrossProjects()
        {
            const string json = """
        [
          { "ok": true, "projectName": "A", "vulnerabilities": [] },
          { "ok": false, "projectName": "B", "vulnerabilities": [
            { "id": "SNYK-3", "title": "Path traversal", "severity": "high", "packageName": "Baz", "version": "3.0.0" }
          ] }
        ]
        """;

            var result = SnykScanResult.Parse(json);

            Assert.False(result.Failed);
            Assert.Equal(2, result.Projects.Count);
            Assert.Equal(1, result.CountAtOrAbove(SnykSeverity.High));
            Assert.Equal(0, result.CountAtOrAbove(SnykSeverity.Critical));
        }

        [Fact]
        public void Parse_EmptyOrGarbage_ReportsFailure()
        {
            Assert.True(SnykScanResult.Parse("").Failed);
            Assert.True(SnykScanResult.Parse("not json").Failed);
        }
    }
}
