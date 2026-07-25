using SnykGhe.Core.Configuration;
using SnykGhe.Core.Snyk;

namespace SnykGhe.Core.Tests
{
    public class ScanEngineValidationTests
    {
        [Fact]
        public void Iac_OnApiEngine_IsRejected()
        {
            var options = new SnykOptions { Engines = new ScanEngineOptions { Iac = ScanEngine.Api } };

            var ex = Assert.Throws<InvalidOperationException>(() => SnykServiceCollectionExtensions.ValidateEngines(options));
            Assert.Contains("Snyk:Engines:Iac", ex.Message);
        }

        [Fact]
        public void Code_OnApiEngine_RequiresAnScmIntegrationId()
        {
            var options = new SnykOptions { Engines = new ScanEngineOptions { Code = ScanEngine.Api } };

            var ex = Assert.Throws<InvalidOperationException>(() => SnykServiceCollectionExtensions.ValidateEngines(options));
            Assert.Contains("Snyk:ScmIntegrationId", ex.Message);
        }

        [Fact]
        public void Code_OnApiEngine_IsAcceptedWithAnScmIntegrationId()
        {
            var options = new SnykOptions
            {
                Engines = new ScanEngineOptions { Code = ScanEngine.Api },
                ScmIntegrationId = "7f44ee57-3092-4584-99f3-3b67f70efeaa",
            };

            SnykServiceCollectionExtensions.ValidateEngines(options);
        }

        [Fact]
        public void OpenSource_OnApiEngine_NeedsNoExtraConfiguration()
        {
            var options = new SnykOptions { Engines = new ScanEngineOptions { OpenSource = ScanEngine.Api } };

            SnykServiceCollectionExtensions.ValidateEngines(options);
        }

        [Fact]
        public void Defaults_AreCliForEveryProduct()
        {
            var engines = new SnykOptions().Engines;

            Assert.Equal(ScanEngine.Cli, engines.OpenSource);
            Assert.Equal(ScanEngine.Cli, engines.Code);
            Assert.Equal(ScanEngine.Cli, engines.Iac);
        }

        [Theory]
        [InlineData("2024-10-15~beta")]
        [InlineData("2024-10-15~experimental")]
        public void PreReleaseApiVersion_IsRejected(string version)
        {
            var options = new SnykOptions { RestApiVersion = version };

            var ex = Assert.Throws<InvalidOperationException>(() => SnykServiceCollectionExtensions.ValidateApiVersion(options));
            Assert.Contains("pre-release", ex.Message);
        }

        [Fact]
        public void DefaultApiVersion_IsGaAndAccepted()
        {
            var options = new SnykOptions();

            Assert.DoesNotContain('~', options.RestApiVersion);
            SnykServiceCollectionExtensions.ValidateApiVersion(options);
        }
    }
}
