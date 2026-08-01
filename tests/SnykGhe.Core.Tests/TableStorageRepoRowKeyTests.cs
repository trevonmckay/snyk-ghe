using SnykGhe.Core.Storage;

namespace SnykGhe.Core.Tests
{
    public class TableStorageRepoRowKeyTests
    {
        [Theory]
        [InlineData("Propel", "atlas-multiplatform")]
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
            Assert.Equal("propel:atlas-multiplatform", TableStorageGitHubInstallationRegistry.RepoRowKey("Propel", "Atlas-Multiplatform"));
        }
    }
}
