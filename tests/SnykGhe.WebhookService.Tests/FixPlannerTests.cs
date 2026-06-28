using SnykGhe.WebhookService.Fix;
using SnykGhe.WebhookService.Snyk;

namespace SnykGhe.WebhookService.Tests
{
    public class FixPlannerTests
    {
        [Fact]
        public void Plan_DirectDependency_TakesHighestTargetAndUnionsVulns()
        {
            const string json = """
        {
          "ok": false,
          "vulnerabilities": [
            { "id": "SNYK-1", "severity": "high", "packageName": "Newtonsoft.Json", "version": "9.0.1",
              "isUpgradable": true, "fixedIn": ["11.0.1"],
              "from": ["proj@0.0.0", "Newtonsoft.Json@9.0.1"],
              "upgradePath": [false, "Newtonsoft.Json@11.0.1"] },
            { "id": "SNYK-2", "severity": "critical", "packageName": "Newtonsoft.Json", "version": "9.0.1",
              "isUpgradable": true, "fixedIn": ["13.0.1"],
              "from": ["proj@0.0.0", "Newtonsoft.Json@9.0.1"],
              "upgradePath": [false, "Newtonsoft.Json@13.0.1"] }
          ]
        }
        """;

            var plan = new FixPlanner().Plan(SnykScanResult.Parse(json));

            var upgrade = Assert.Single(plan.Upgrades);
            Assert.Equal("Newtonsoft.Json", upgrade.PackageName);
            Assert.Equal("9.0.1", upgrade.FromVersion);
            Assert.Equal("13.0.1", upgrade.ToVersion); // highest of 11.0.1 / 13.0.1
            Assert.Equal(2, upgrade.VulnerabilityIds.Count);
        }

        [Fact]
        public void Plan_TransitiveVuln_UpgradesTheDirectDependency()
        {
            const string json = """
        {
          "ok": false,
          "vulnerabilities": [
            { "id": "SNYK-T", "severity": "critical", "packageName": "System.Net.Vuln", "version": "1.0.0",
              "isUpgradable": true, "fixedIn": ["1.1.0"],
              "from": ["proj@0.0.0", "Some.Direct@2.0.0", "System.Net.Vuln@1.0.0"],
              "upgradePath": [false, "Some.Direct@2.1.0", "System.Net.Vuln@1.1.0"] }
          ]
        }
        """;

            var plan = new FixPlanner().Plan(SnykScanResult.Parse(json));

            var upgrade = Assert.Single(plan.Upgrades);
            Assert.Equal("Some.Direct", upgrade.PackageName);
            Assert.Equal("2.1.0", upgrade.ToVersion);
        }

        [Fact]
        public void Plan_NonUpgradableVuln_IsIgnored()
        {
            const string json = """
        {
          "ok": false,
          "vulnerabilities": [
            { "id": "SNYK-N", "severity": "high", "packageName": "Stuck.Pkg", "version": "1.0.0",
              "isUpgradable": false, "from": ["proj@0.0.0", "Stuck.Pkg@1.0.0"],
              "upgradePath": [false, false] }
          ]
        }
        """;

            var plan = new FixPlanner().Plan(SnykScanResult.Parse(json));

            Assert.False(plan.HasUpgrades);
        }
    }
}
