using SnykGhe.Core.Snyk;

namespace SnykGhe.Core.Tests
{
    public class SnykMonitorResultTests
    {
        [Fact]
        public void FirstUri_SingleProjectObject_ReturnsUri()
        {
            const string json = """
        { "ok": true, "projectName": "Acme.Api", "isMonitored": true, "uri": "https://app.snyk.io/org/acme/project/abc-123/history/snap-1" }
        """;

            Assert.Equal("https://app.snyk.io/org/acme/project/abc-123/history/snap-1", SnykMonitorResult.FirstUri(json));
        }

        [Fact]
        public void FirstUri_AllProjectsArray_ReturnsFirstWithUri()
        {
            const string json = """
        [
          { "ok": true, "projectName": "A", "uri": "https://app.snyk.io/org/acme/project/a-1" },
          { "ok": true, "projectName": "B", "uri": "https://app.snyk.io/org/acme/project/b-2" }
        ]
        """;

            Assert.Equal("https://app.snyk.io/org/acme/project/a-1", SnykMonitorResult.FirstUri(json));
        }

        [Fact]
        public void FirstUri_SkipsEntriesWithoutUri()
        {
            const string json = """
        [
          { "ok": false, "projectName": "A" },
          { "ok": true, "projectName": "B", "uri": "https://app.snyk.io/org/acme/project/b-2" }
        ]
        """;

            Assert.Equal("https://app.snyk.io/org/acme/project/b-2", SnykMonitorResult.FirstUri(json));
        }

        [Fact]
        public void FirstUri_EmptyOrUnparseableOrNoUri_ReturnsNull()
        {
            Assert.Null(SnykMonitorResult.FirstUri(""));
            Assert.Null(SnykMonitorResult.FirstUri("not json"));
            Assert.Null(SnykMonitorResult.FirstUri("""{ "ok": true, "projectName": "A" }"""));
            Assert.Null(SnykMonitorResult.FirstUri("[]"));
        }
    }
}
