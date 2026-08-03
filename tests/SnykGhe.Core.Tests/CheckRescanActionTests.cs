using SnykGhe.Core.Processing;
using SnykGhe.Core.Snyk;

namespace SnykGhe.Core.Tests
{
    public class CheckRescanActionTests
    {
        [Theory]
        [InlineData(SnykProduct.OpenSource, "Re-run Snyk Open-source scan")]
        [InlineData(SnykProduct.Code, "Re-run Snyk SAST scan")]
        [InlineData(SnykProduct.Iac, "Re-run Snyk IaC scan")]
        public void RescanDescription_IsProductSpecific(SnykProduct product, string expected)
        {
            Assert.Equal(expected, PullRequestCheckService.RescanDescription(product));
        }

        [Theory]
        [InlineData(SnykProduct.OpenSource)]
        [InlineData(SnykProduct.Code)]
        [InlineData(SnykProduct.Iac)]
        public void RescanDescription_WithinGitHubActionLimit(SnykProduct product)
        {
            // GitHub rejects a check-run action whose description exceeds 40 characters with HTTP 422.
            Assert.InRange(PullRequestCheckService.RescanDescription(product).Length, 1, 40);
        }

        [Fact]
        public void RescanActionIdentifier_WithinGitHubLimit()
        {
            // GitHub caps the action identifier at 20 characters.
            Assert.InRange(PullRequestCheckService.RescanActionIdentifier.Length, 1, 20);
        }
    }
}
