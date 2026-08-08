using Microsoft.Extensions.Options;
using SnykGhe.Core.Configuration;

namespace SnykGhe.Core.Tests
{
    public class AuthOptionsValidatorTests
    {
        private static ValidateOptionsResult Validate(AuthOptions auth)
        {
            return new AuthOptionsValidator().Validate(null, auth);
        }

        [Fact]
        public void NoMethods_IsNotAStartupError_AdminApiJustClosed()
        {
            // An empty method set is a valid "I won't use the admin endpoints" state; the app still starts
            // and the admin API is closed.
            Assert.True(Validate(new AuthOptions { Methods = [] }).Succeeded);
        }

        [Fact]
        public void UnknownMethod_Fails()
        {
            // A typo'd method name would silently do nothing, so it is surfaced loudly.
            Assert.True(Validate(new AuthOptions { Methods = ["Basic"] }).Failed);
        }

        [Fact]
        public void AdminKey_BlankKey_IsNotAStartupError_JustClosed()
        {
            // A blank admin key closes the AdminKey path (nothing can authenticate with it); the app still
            // starts. The key's presence is not a config-validation concern.
            Assert.True(Validate(new AuthOptions { Methods = ["AdminKey"] }).Succeeded);
        }

        [Fact]
        public void MethodNames_AreCaseInsensitive()
        {
            Assert.True(Validate(new AuthOptions { Methods = ["adminkey"] }).Succeeded);
        }

        [Fact]
        public void OAuth2_MissingAuthorityAndAudience_Fails()
        {
            Assert.True(Validate(new AuthOptions { Methods = ["OAuth2"] }).Failed);
        }

        [Fact]
        public void OAuth2_MissingAudience_Fails()
        {
            var auth = new AuthOptions
            {
                Methods = ["OAuth2"],
                OAuth2 = new OAuth2Options { Authority = "https://issuer.example/" },
            };
            Assert.True(Validate(auth).Failed);
        }

        [Fact]
        public void OAuth2_Complete_Succeeds()
        {
            var auth = new AuthOptions
            {
                Methods = ["OAuth2"],
                OAuth2 = new OAuth2Options { Authority = "https://issuer.example/", Audience = "api://snyk-ghe" },
            };
            Assert.True(Validate(auth).Succeeded);
        }

        [Fact]
        public void BothMethods_AllSettingsPresent_Succeeds()
        {
            var auth = new AuthOptions
            {
                Methods = ["AdminKey", "OAuth2"],
                OAuth2 = new OAuth2Options { Authority = "https://issuer.example/", Audience = "api://snyk-ghe" },
            };
            Assert.True(Validate(auth).Succeeded);
        }
    }
}
