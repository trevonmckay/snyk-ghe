using SnykGhe.Core.Snyk;

namespace SnykGhe.Core.Tests
{
    public class SnykIacResultTests
    {
        [Fact]
        public void Parse_ArrayOfFiles_AggregatesIssuesWithLocations()
        {
            const string json = """
        [
          { "targetFile": "main.tf", "infrastructureAsCodeIssues": [
              { "id": "SNYK-CC-TF-1", "title": "S3 bucket without encryption", "severity": "high", "lineNumber": 12 },
              { "id": "SNYK-CC-TF-2", "title": "Public security group", "severity": "medium", "lineNumber": -1 }
          ] },
          { "targetFile": "k8s.yaml", "infrastructureAsCodeIssues": [
              { "id": "SNYK-CC-K8S-1", "title": "Privileged container", "severity": "critical", "lineNumber": 5 }
          ] }
        ]
        """;

            var result = SnykIacResult.Parse(json);

            Assert.False(result.Failed);
            Assert.Equal(SnykProduct.Iac, result.Product);
            Assert.Equal(3, result.Findings.Count);

            Assert.Equal("high", result.Findings[0].Severity);
            Assert.Equal("main.tf:12", result.Findings[0].Location);

            // lineNumber -1 (unknown) falls back to just the file path.
            Assert.Equal("main.tf", result.Findings[1].Location);

            Assert.Equal("critical", result.Findings[2].Severity);
            Assert.Equal("k8s.yaml:5", result.Findings[2].Location);

            Assert.Equal(2, result.CountAtOrAbove(SnykSeverity.High));
        }

        [Fact]
        public void Parse_SingleFileObject_IsSupported()
        {
            const string json = """
        { "targetFile": "main.tf", "infrastructureAsCodeIssues": [
            { "title": "Open ingress", "severity": "low", "lineNumber": 3 }
        ] }
        """;

            var result = SnykIacResult.Parse(json);

            Assert.Single(result.Findings);
            Assert.Equal("main.tf:3", result.Findings[0].Location);
        }

        [Fact]
        public void Parse_EmptyArrayOrGarbage_HandledGracefully()
        {
            Assert.Empty(SnykIacResult.Parse("[]").Findings);
            Assert.Empty(SnykIacResult.Parse("").Findings);
            Assert.True(SnykIacResult.Parse("not json").Failed);
        }
    }
}
