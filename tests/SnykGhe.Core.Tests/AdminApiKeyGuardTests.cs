using SnykGhe.Core.Infrastructure;

namespace SnykGhe.Core.Tests
{
    public class AdminApiKeyGuardTests
    {
        [Fact]
        public void Matches_TrueWhenKeysAreEqual()
        {
            Assert.True(AdminApiKeyGuard.Matches("s3cret-key", "s3cret-key"));
        }

        [Fact]
        public void Matches_FalseWhenProvidedKeyIsWrong()
        {
            Assert.False(AdminApiKeyGuard.Matches("wrong", "s3cret-key"));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void Matches_FalseWhenNotConfigured(string? configured)
        {
            // Closed by default: with no configured key, nothing authorizes.
            Assert.False(AdminApiKeyGuard.Matches("anything", configured));
        }

        [Fact]
        public void Matches_FalseWhenProvidedKeyIsNull()
        {
            Assert.False(AdminApiKeyGuard.Matches(null, "s3cret-key"));
        }
    }
}
