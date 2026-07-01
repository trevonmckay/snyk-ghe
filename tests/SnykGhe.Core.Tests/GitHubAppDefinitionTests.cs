using SnykGhe.Core.GitHub.Manifest;

namespace SnykGhe.Core.Tests
{
    public class GitHubAppDefinitionTests
    {
        [Fact]
        public void Events_SubscribesToPullRequestCheckRunDeleteAndPush()
        {
            // pull_request drives the initial scan; check_run (rerequested) backs the "Re-run" button on the
            // Snyk check; delete triggers Snyk branch-reference cleanup; push triggers the default-branch
            // baseline monitor. GitHub only delivers events the App subscribes to, so dropping any silently
            // breaks the corresponding trigger.
            Assert.Contains("pull_request", GitHubAppDefinition.Events);
            Assert.Contains("check_run", GitHubAppDefinition.Events);
            Assert.Contains("delete", GitHubAppDefinition.Events);
            Assert.Contains("push", GitHubAppDefinition.Events);
        }

        [Fact]
        public void Permissions_IncludeChecksWriteForPublishingCheckRuns()
        {
            Assert.Equal("write", GitHubAppDefinition.Permissions["checks"]);
        }
    }
}
