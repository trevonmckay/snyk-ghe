using SnykGhe.Core.Processing;

namespace SnykGhe.Core.Tests
{
    public class BaselineScanRequestTests
    {
        [Theory]
        [InlineData("https://github.com/acme/widgets.git", "https://github.com/acme/widgets")]
        [InlineData("https://github.com/acme/widgets", "https://github.com/acme/widgets")]
        public void RemoteRepoUrl_StripsTrailingGitSuffix(string cloneUrl, string expected)
        {
            // Snyk stores --remote-repo-url verbatim as the target name; a .git suffix would surface as a
            // distinct owner/repo.git target, so the baseline must resolve the same target the PR scan created.
            var request = new BaselineScanRequest
            {
                InstallationId = 1,
                Owner = "acme",
                Repo = "widgets",
                CloneUrl = cloneUrl,
                Branch = "main",
                HeadSha = "abc123",
            };

            Assert.Equal(expected, request.RemoteRepoUrl);
        }
    }
}
