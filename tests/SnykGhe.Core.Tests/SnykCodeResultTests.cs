using SnykGhe.Core.Snyk;

namespace SnykGhe.Core.Tests
{
    public class SnykCodeResultTests
    {
        [Fact]
        public void Parse_Sarif_MapsLevelsToSeverityAndLocations()
        {
            const string json = """
        {
          "version": "2.1.0",
          "runs": [
            {
              "tool": { "driver": { "name": "SnykCode" } },
              "results": [
                { "ruleId": "javascript/Sqli", "level": "error", "message": { "text": "SQL Injection" },
                  "locations": [ { "physicalLocation": { "artifactLocation": { "uri": "src/db.js" }, "region": { "startLine": 42 } } } ] },
                { "ruleId": "javascript/HardcodedSecret", "level": "warning", "message": { "text": "Hardcoded secret" },
                  "locations": [ { "physicalLocation": { "artifactLocation": { "uri": "src/config.js" }, "region": { "startLine": 7 } } } ] },
                { "ruleId": "javascript/Xss", "level": "note", "message": { "text": "XSS" }, "locations": [] }
              ]
            }
          ]
        }
        """;

            var result = SnykCodeResult.Parse(json);

            Assert.False(result.Failed);
            Assert.Equal(SnykProduct.Code, result.Product);
            Assert.Equal(3, result.Findings.Count);

            var sqli = result.Findings[0];
            Assert.Equal("high", sqli.Severity);
            Assert.Equal("SQL Injection", sqli.Title);
            Assert.Equal("src/db.js:42", sqli.Location);

            Assert.Equal("medium", result.Findings[1].Severity);
            Assert.Equal("src/config.js:7", result.Findings[1].Location);

            Assert.Equal("low", result.Findings[2].Severity);
            Assert.Null(result.Findings[2].Location);

            Assert.Equal(1, result.CountAtOrAbove(SnykSeverity.High));
            Assert.Equal(3, result.CountAtOrAbove(SnykSeverity.Low));
        }

        [Fact]
        public void Parse_FallsBackToRuleIdWhenNoMessage()
        {
            const string json = """
        { "runs": [ { "results": [ { "ruleId": "go/NoMessage", "level": "warning" } ] } ] }
        """;

            var result = SnykCodeResult.Parse(json);

            Assert.Single(result.Findings);
            Assert.Equal("go/NoMessage", result.Findings[0].Title);
            Assert.Null(result.Findings[0].Location);
        }

        [Fact]
        public void Parse_NoResults_IsCleanPass()
        {
            var result = SnykCodeResult.Parse("""{ "version": "2.1.0", "runs": [ { "results": [] } ] }""");

            Assert.False(result.Failed);
            Assert.Empty(result.Findings);
        }

        [Fact]
        public void Parse_EmptyOrGarbage_HandledGracefully()
        {
            Assert.Empty(SnykCodeResult.Parse("").Findings);
            Assert.True(SnykCodeResult.Parse("not json").Failed);
        }
    }
}
