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
    }
}
