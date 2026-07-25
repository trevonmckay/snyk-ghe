using System.Text.Json.Nodes;

namespace Snyk.Client.Tests
{
    /// <summary>Optional per-test configuration layered over the org's own settings.</summary>
    public sealed class SnykTestConfiguration
    {
        /// <summary>
        /// Publish findings to a report visible in the Snyk Web UI. When false the test is "stateless" and
        /// no project output is produced; combining false with <see cref="TargetReference"/> is rejected.
        /// </summary>
        public bool? PublishReport { get; init; }

        public string? TargetName { get; init; }

        /// <summary>Reference (typically a branch) that groups a published project's snapshots.</summary>
        public string? TargetReference { get; init; }

        /// <summary>Findings at or above this severity fail the test. Omit to report every severity and gate in caller code.</summary>
        public string? SeverityThreshold { get; init; }

        public IReadOnlyList<string>? ProjectTags { get; init; }

        internal JsonObject ToJson(IReadOnlyCollection<SnykScanner> scanners)
        {
            var config = new JsonObject();

            if (PublishReport is not null)
            {
                config["publish_report"] = PublishReport.Value;
            }

            if (!string.IsNullOrWhiteSpace(TargetName))
            {
                config["target_name"] = TargetName;
            }

            if (!string.IsNullOrWhiteSpace(TargetReference))
            {
                config["target_reference"] = TargetReference;
            }

            if (!string.IsNullOrWhiteSpace(SeverityThreshold))
            {
                config["local_policy"] = new JsonObject
                {
                    ["suppress_pending_ignores"] = false,
                    ["severity_threshold"] = SeverityThreshold,
                };
            }

            if (ProjectTags is { Count: > 0 })
            {
                var tags = new JsonArray();
                foreach (var tag in ProjectTags)
                {
                    tags.Add(tag);
                }

                config["project_tags"] = tags;
            }

            // An omitted scanner config means "do not run that scanner"; an empty object means "run it".
            var scanConfig = new JsonObject();
            foreach (var scanner in scanners)
            {
                scanConfig[ScannerKey(scanner)] = new JsonObject();
            }

            config["scan_config"] = scanConfig;
            return config;
        }

        private static string ScannerKey(SnykScanner scanner) => scanner switch
        {
            SnykScanner.Sca => "sca",
            SnykScanner.Sast => "sast",
            SnykScanner.Iac => "iac",
            SnykScanner.Container => "container",
            SnykScanner.Secrets => "secrets",
            _ => throw new ArgumentOutOfRangeException(nameof(scanner), scanner, "Unknown Snyk scanner."),
        };
    }

    /// <summary>A request to create a test: what to scan, and which scanners to run over it.</summary>
    public sealed class SnykTestRequest
    {
        public required IReadOnlyList<TestResource> Resources { get; init; }

        public required IReadOnlyList<SnykScanner> Scanners { get; init; }

        public SnykTestConfiguration? Configuration { get; init; }

        public SdlcStage Stage { get; init; } = SdlcStage.Other;

        internal string ToJson()
        {
            if (Resources.Count == 0)
            {
                throw new ArgumentException("A Snyk test requires at least one resource.", nameof(Resources));
            }

            if (Scanners.Count == 0)
            {
                throw new ArgumentException("A Snyk test requires at least one scanner.", nameof(Scanners));
            }

            var resources = new JsonArray();
            foreach (var resource in Resources)
            {
                resources.Add(resource.ToJson());
            }

            var attributes = new JsonObject
            {
                ["sdlc_stage"] = StageKey(Stage),
                ["resources"] = resources,
                ["config"] = (Configuration ?? new SnykTestConfiguration()).ToJson(Scanners.ToList()),
            };

            var body = new JsonObject
            {
                ["data"] = new JsonObject
                {
                    ["type"] = "tests",
                    ["attributes"] = attributes,
                },
            };

            return body.ToJsonString();
        }

        private static string StageKey(SdlcStage stage) => stage switch
        {
            SdlcStage.Ide => "ide",
            SdlcStage.Cli => "cli",
            SdlcStage.PrCheck => "pr_check",
            SdlcStage.CiCd => "ci_cd",
            SdlcStage.Mcp => "mcp",
            SdlcStage.Other => "other",
            _ => throw new ArgumentOutOfRangeException(nameof(stage), stage, "Unknown SDLC stage."),
        };
    }
}
