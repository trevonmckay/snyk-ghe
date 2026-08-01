using SnykGhe.Core.Configuration;
using SnykGhe.Core.Snyk;

namespace SnykGhe.Core.Tests
{
    public class SnykCliRunnerArgsTests
    {
        private static ResolvedPolicy Policy(params string[] excludeDirs) => new()
        {
            GitHubOrg = "acme",
            SeverityThreshold = "high",
            Ecosystem = "nuget",
            ExcludeDirs = excludeDirs,
        };

        [Fact]
        public void AddExcludeArgs_NoExcludes_AddsNothing()
        {
            var args = new List<string> { "test" };

            SnykCliRunner.AddExcludeArgs(args, Policy());

            Assert.Equal(["test"], args);
        }

        [Fact]
        public void AddExcludeArgs_WithExcludes_AddsCommaSeparatedNames()
        {
            var args = new List<string> { "test" };

            SnykCliRunner.AddExcludeArgs(args, Policy("obj", "docling-sidecar"));

            Assert.Equal(["test", "--exclude=obj,docling-sidecar"], args);
        }
    }
}
