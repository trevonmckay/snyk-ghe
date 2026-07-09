using SnykGhe.Core.Processing;

namespace SnykGhe.Core.Tests
{
    public class BaselineScanMessageTests
    {
        [Fact]
        public void SerializeRoundTrip_PreservesRequestFields()
        {
            var original = new BaselineScanRequest
            {
                InstallationId = 4242,
                Owner = "acme",
                Repo = "widgets",
                CloneUrl = "https://github.com/acme/widgets.git",
                Branch = "release/1.x",
                HeadSha = "abc123",
            };

            var restored = BaselineScanMessage.Deserialize(BaselineScanMessage.Serialize(original));

            Assert.NotNull(restored);
            Assert.Equal(original.InstallationId, restored!.InstallationId);
            Assert.Equal(original.Owner, restored.Owner);
            Assert.Equal(original.Repo, restored.Repo);
            Assert.Equal(original.CloneUrl, restored.CloneUrl);
            Assert.Equal(original.Branch, restored.Branch);
            Assert.Equal(original.HeadSha, restored.HeadSha);
            // Derived from CloneUrl on the consumer side (JsonIgnored, so it survives without being serialized).
            Assert.Equal("https://github.com/acme/widgets", restored.RemoteRepoUrl);
        }

        [Fact]
        public void EventName_CannotCollideWithAGitHubEvent()
        {
            // GitHub X-GitHub-Event values are bare tokens; the vendor-namespaced slash guarantees no real
            // delivery is ever routed down the baseline path.
            Assert.Contains('/', BaselineScanMessage.EventName);
        }
    }
}
