using Microsoft.Extensions.Options;
using SnykGhe.Core.Configuration;
using SnykGhe.Core.GitHub.Manifest;

namespace SnykGhe.Core.Tests
{
    public class GitHubAppManifestServiceTests
    {
        private static GitHubAppManifestService Build()
        {
            var options = Options.Create(new GitHubOptions { ApiBaseUrl = "https://api.example.ghe.com/" });
            return new GitHubAppManifestService(new HttpClient(), options);
        }

        [Fact]
        public void BuildManifest_NoWebhookOverride_DerivesHookUrlFromBaseUrl()
        {
            var manifest = Build().BuildManifest("snyk-ghe", "https://snyk-ghe.example.com/");

            Assert.Equal("https://snyk-ghe.example.com/api/github/webhooks", manifest.HookAttributes.Url);
            Assert.Equal("https://snyk-ghe.example.com/api/github/app/created", manifest.RedirectUrl);
            Assert.Equal("https://snyk-ghe.example.com/api/github/setup", manifest.SetupUrl);
            // Must be public: the app serves many orgs (a private app installs only on its owner) and EMU
            // enterprises reject a private app.
            Assert.True(manifest.Public);
        }

        [Fact]
        public void BuildManifest_WithWebhookOverride_PointsHookAtOverrideButKeepsBaseUrlForCallbacks()
        {
            // Scale-to-zero topology: webhooks go to the Function front door, registration callbacks to the
            // Container App. The override must not leak into redirect/setup, or GitHub redirects to the wrong host.
            var manifest = Build().BuildManifest(
                "snyk-ghe",
                "https://snyk-ghe-app.region.azurecontainerapps.io",
                "https://snyk-ghe-fn.azurewebsites.net/api/github/webhooks");

            Assert.Equal("https://snyk-ghe-fn.azurewebsites.net/api/github/webhooks", manifest.HookAttributes.Url);
            Assert.Equal("https://snyk-ghe-app.region.azurecontainerapps.io/api/github/app/created", manifest.RedirectUrl);
            Assert.Equal("https://snyk-ghe-app.region.azurecontainerapps.io/api/github/setup", manifest.SetupUrl);
        }

        [Theory]
        [InlineData("")]
        [InlineData("   ")]
        public void BuildManifest_BlankWebhookOverride_FallsBackToBaseUrl(string webhookUrl)
        {
            var manifest = Build().BuildManifest("snyk-ghe", "https://snyk-ghe.example.com", webhookUrl);

            Assert.Equal("https://snyk-ghe.example.com/api/github/webhooks", manifest.HookAttributes.Url);
        }
    }
}
