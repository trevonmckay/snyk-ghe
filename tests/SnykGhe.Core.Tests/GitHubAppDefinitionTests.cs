using SnykGhe.Core.GitHub.Manifest;

namespace SnykGhe.Core.Tests
{
    public class GitHubAppDefinitionTests
    {
        [Fact]
        public void Events_SubscribesToPullRequestAndCheckRun()
        {
            // pull_request drives the initial scan; check_run (rerequested) backs the "Re-run" button on the
            // Snyk check. GitHub only delivers events the App subscribes to, so dropping either silently
            // breaks the corresponding trigger.
            Assert.Contains("pull_request", GitHubAppDefinition.Events);
            Assert.Contains("check_run", GitHubAppDefinition.Events);
        }

        [Fact]
        public void Permissions_IncludeChecksWriteForPublishingCheckRuns()
        {
            Assert.Equal("write", GitHubAppDefinition.Permissions["checks"]);
        }
    }
}
