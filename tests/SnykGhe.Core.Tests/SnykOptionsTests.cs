using Microsoft.Extensions.Configuration;
using SnykGhe.Core.Configuration;

namespace SnykGhe.Core.Tests
{
    public class SnykOptionsTests
    {
        [Fact]
        public void MonitorTimeoutSeconds_DefaultsToFifteenMinutes()
        {
            var options = new SnykOptions();

            Assert.Equal(900, options.MonitorTimeoutSeconds);
        }

        [Fact]
        public void MonitorTimeoutSeconds_BindsFromConfiguration()
        {
            var config = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Snyk:MonitorTimeoutSeconds"] = "1200",
                })
                .Build();

            var options = new SnykOptions();
            config.GetSection(SnykOptions.SectionName).Bind(options);

            Assert.Equal(1200, options.MonitorTimeoutSeconds);
        }

        [Fact]
        public void ScanRetry_DefaultsToOneRetryAfterFifteenSeconds()
        {
            var options = new SnykOptions();

            Assert.Equal(1, options.ScanMaxRetries);
            Assert.Equal(15, options.ScanRetryDelaySeconds);
        }

        [Fact]
        public void ScanRetry_BindsFromConfiguration()
        {
            var config = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Snyk:ScanMaxRetries"] = "0",
                    ["Snyk:ScanRetryDelaySeconds"] = "30",
                })
                .Build();

            var options = new SnykOptions();
            config.GetSection(SnykOptions.SectionName).Bind(options);

            Assert.Equal(0, options.ScanMaxRetries);
            Assert.Equal(30, options.ScanRetryDelaySeconds);
        }

        [Fact]
        public void CleanupOnPullRequestClose_DefaultsToTrue()
        {
            var options = new SnykOptions();

            Assert.True(options.CleanupOnPullRequestClose);
        }

        [Fact]
        public void CleanupOnPullRequestClose_BindsFromConfiguration()
        {
            var config = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Snyk:CleanupOnPullRequestClose"] = "false",
                })
                .Build();

            var options = new SnykOptions();
            config.GetSection(SnykOptions.SectionName).Bind(options);

            Assert.False(options.CleanupOnPullRequestClose);
        }
    }
}
