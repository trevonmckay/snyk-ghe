using SnykGhe.Core.Snyk;

namespace SnykGhe.Core.Tests
{
    public class DepGraphGeneratorTests
    {
        /// <summary>Shape emitted by `snyk test --print-graph --all-projects`, captured from the CLI.</summary>
        private const string CliOutput = """
            DepGraph data:
            {"schemaVersion":"1.3.0","pkgManager":{"name":"nuget"},"pkgs":[{"id":"a@1.0.0","info":{"name":"a","version":"1.0.0"}}],"graph":{"rootNodeId":"root-node","nodes":[{"nodeId":"root-node","pkgId":"a@1.0.0","deps":[]}]}}
            DepGraph target:
            src\Alpha\obj\project.assets.json
            DepGraph end

            DepGraph data:
            {"schemaVersion":"1.3.0","pkgManager":{"name":"nuget"},"pkgs":[{"id":"b@2.0.0","info":{"name":"b","version":"2.0.0"}}],"graph":{"rootNodeId":"root-node","nodes":[{"nodeId":"root-node","pkgId":"b@2.0.0","deps":[]}]}}
            DepGraph target:
            src\Beta\obj\project.assets.json
            DepGraph end
            """;

        [Fact]
        public void Parse_ExtractsOneGraphPerProjectWithItsTargetName()
        {
            var graphs = DepGraphGenerator.Parse(CliOutput);

            Assert.Equal(2, graphs.Count);
            Assert.Equal(@"src\Alpha\obj\project.assets.json", graphs[0].Name);
            Assert.Equal(@"src\Beta\obj\project.assets.json", graphs[1].Name);
            Assert.Equal("1.3.0", graphs[0].Graph["schemaVersion"]!.GetValue<string>());
            Assert.Equal("nuget", graphs[0].Graph["pkgManager"]!["name"]!.GetValue<string>());
        }

        [Fact]
        public void Parse_IgnoresSurroundingHumanReadableText()
        {
            var output = "Testing /repo...\n" + CliOutput + "\n\nTested 2 projects, no vulnerable paths found.";

            var graphs = DepGraphGenerator.Parse(output);

            Assert.Equal(2, graphs.Count);
        }

        /// <summary>Nested objects and braces inside strings must not terminate the scan early.</summary>
        [Fact]
        public void Parse_HandlesNestedBracesAndBracesInsideStrings()
        {
            var output = """
                DepGraph data:
                {"schemaVersion":"1.3.0","note":"a } brace \" in a string","graph":{"nodes":[{"nodeId":"root-node"}]}}
                DepGraph target:
                package.json
                DepGraph end
                """;

            var graph = Assert.Single(DepGraphGenerator.Parse(output));
            Assert.Equal("package.json", graph.Name);
            Assert.Equal("a } brace \" in a string", graph.Graph["note"]!.GetValue<string>());
        }

        [Fact]
        public void Parse_FallsBackToAnOrdinalName_WhenTargetBannerIsAbsent()
        {
            var output = """
                DepGraph data:
                {"schemaVersion":"1.3.0"}
                """;

            var graph = Assert.Single(DepGraphGenerator.Parse(output));
            Assert.Equal("dep-graph-1.json", graph.Name);
        }

        [Fact]
        public void Parse_ReturnsEmpty_ForOutputWithNoGraphs()
        {
            Assert.Empty(DepGraphGenerator.Parse(string.Empty));
            Assert.Empty(DepGraphGenerator.Parse("Authentication error."));
        }

        /// <summary>
        /// A generator that could not run must report failure rather than "no graphs" — the API scanner turns
        /// an empty-but-successful result into a passing check, so a silent empty here would report a clean
        /// scan for a repository that was never scanned.
        /// </summary>
        [Fact]
        public void FromOutcome_AuthenticationFailure_IsAFailureNotAnEmptyResult()
        {
            var result = DepGraphGenerator.FromOutcome(new SnykCliOutcome { AuthenticationFailed = true });

            Assert.True(result.Failed);
            Assert.Empty(result.Graphs);
            Assert.Contains("authentication", result.FailureMessage!, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void FromOutcome_Timeout_IsAFailure()
        {
            var result = DepGraphGenerator.FromOutcome(new SnykCliOutcome { TimedOut = true });

            Assert.True(result.Failed);
            Assert.Contains("timed out", result.FailureMessage!, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>Exit 2 (CLI error) and exit 3 (no supported manifests) both fail the CLI scanner; match it.</summary>
        [Theory]
        [InlineData(2, "Unknown command")]
        [InlineData(3, "Could not find any supported files")]
        public void FromOutcome_CliErrorExitCodes_AreFailures(int exitCode, string stderr)
        {
            var result = DepGraphGenerator.FromOutcome(new SnykCliOutcome { ExitCode = exitCode, StandardError = stderr });

            Assert.True(result.Failed);
            Assert.Equal(stderr, result.FailureMessage);
        }

        /// <summary>Exit 1 means vulnerabilities were found; the graphs are still printed and must be used.</summary>
        [Fact]
        public void FromOutcome_ExitOne_StillYieldsGraphs()
        {
            var result = DepGraphGenerator.FromOutcome(new SnykCliOutcome { ExitCode = 1, StandardOutput = CliOutput });

            Assert.False(result.Failed);
            Assert.Equal(2, result.Graphs.Count);
        }

        [Fact]
        public void FromOutcome_CleanExitWithNoManifests_IsSuccessWithNoGraphs()
        {
            var result = DepGraphGenerator.FromOutcome(new SnykCliOutcome { ExitCode = 0, StandardOutput = string.Empty });

            Assert.False(result.Failed);
            Assert.Empty(result.Graphs);
        }
    }
}
