using SnykGhe.Core.Storage;

namespace SnykGhe.Core.Tests
{
    public class TableStorageRepoRowKeyTests
    {
        [Theory]
        [InlineData("acme", "sample-repo")]
        [InlineData("Acme", "web.app")]
        [InlineData("Org-Name", "repo_name")]
        public void RepoRowKey_ContainsNoTableIllegalCharacters(string org, string repo)
        {
            var key = TableStorageGitHubInstallationRegistry.RepoRowKey(org, repo);

            // Azure Table Storage rejects these in a PartitionKey/RowKey with "InvalidInput".
            foreach (var illegal in new[] { '/', '\\', '#', '?' })
            {
                Assert.DoesNotContain(illegal, key);
            }
        }

        [Fact]
        public void RepoRowKey_IsNormalizedAndStable()
        {
            Assert.Equal("acme:sample-repo", TableStorageGitHubInstallationRegistry.RepoRowKey("acme", "Sample-Repo"));
        }
    }
}
