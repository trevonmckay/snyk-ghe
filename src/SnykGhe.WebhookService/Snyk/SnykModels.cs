using System.Text.Json;
using System.Text.Json.Serialization;

namespace SnykGhe.WebhookService.Snyk
{
    /// <summary>A single vulnerability from `snyk test --json`.</summary>
    public sealed class SnykVulnerability
    {
        [JsonPropertyName("id")] public string Id { get; set; } = string.Empty;
        [JsonPropertyName("title")] public string Title { get; set; } = string.Empty;
        [JsonPropertyName("severity")] public string Severity { get; set; } = string.Empty;
        [JsonPropertyName("packageName")] public string PackageName { get; set; } = string.Empty;
        [JsonPropertyName("version")] public string Version { get; set; } = string.Empty;
        [JsonPropertyName("isUpgradable")] public bool IsUpgradable { get; set; }
        [JsonPropertyName("isPatchable")] public bool IsPatchable { get; set; }
        [JsonPropertyName("fixedIn")] public List<string>? FixedIn { get; set; }

        /// <summary>Dependency path: index 0 is the project, index 1 the direct dependency ("pkg@version").</summary>
        [JsonPropertyName("from")] public List<string>? From { get; set; }

        /// <summary>Per-hop upgrade targets aligned to <see cref="From"/>; entries are either false or "pkg@version".</summary>
        [JsonPropertyName("upgradePath")] public List<JsonElement>? UpgradePath { get; set; }
    }

    /// <summary>Result for a single project/manifest from `snyk test --json`.</summary>
    public sealed class SnykProjectResult
    {
        [JsonPropertyName("ok")] public bool Ok { get; set; }
        [JsonPropertyName("projectName")] public string? ProjectName { get; set; }
        [JsonPropertyName("displayTargetFile")] public string? TargetFile { get; set; }
        [JsonPropertyName("vulnerabilities")] public List<SnykVulnerability> Vulnerabilities { get; set; } = [];
        [JsonPropertyName("error")] public string? Error { get; set; }
    }

    /// <summary>Aggregated outcome of a scan across one or more manifests.</summary>
    public sealed class SnykScanResult
    {
        public required IReadOnlyList<SnykProjectResult> Projects { get; init; }

        /// <summary>True when the CLI ran but produced no parseable JSON (e.g. a config/auth error).</summary>
        public bool Failed { get; init; }

        public string? FailureMessage { get; init; }

        public IEnumerable<SnykVulnerability> AllVulnerabilities =>
            Projects.SelectMany(p => p.Vulnerabilities);

        public int CountAtOrAbove(SnykSeverity threshold) =>
            AllVulnerabilities.Count(v => SnykSeverityExtensions.Parse(v.Severity) >= threshold);

        /// <summary>
        /// Parses `snyk test --json` output, which is a single object for one project or a JSON array
        /// when --all-projects discovers multiple manifests.
        /// </summary>
        public static SnykScanResult Parse(string json)
        {
            if (string.IsNullOrWhiteSpace(json))
            {
                return new SnykScanResult { Projects = [], Failed = true, FailureMessage = "Empty Snyk output." };
            }

            try
            {
                using var doc = JsonDocument.Parse(json);
                var projects = doc.RootElement.ValueKind == JsonValueKind.Array
                    ? doc.RootElement.EnumerateArray()
                        .Select(e => e.Deserialize<SnykProjectResult>()!)
                        .ToList()
                    : [doc.RootElement.Deserialize<SnykProjectResult>()!];

                return new SnykScanResult { Projects = projects };
            }
            catch (JsonException ex)
            {
                return new SnykScanResult { Projects = [], Failed = true, FailureMessage = ex.Message };
            }
        }
    }

    public enum SnykSeverity
    {
        Unknown = 0,
        Low = 1,
        Medium = 2,
        High = 3,
        Critical = 4,
    }

    public static class SnykSeverityExtensions
    {
        public static SnykSeverity Parse(string? value) => value?.ToLowerInvariant() switch
        {
            "low" => SnykSeverity.Low,
            "medium" => SnykSeverity.Medium,
            "high" => SnykSeverity.High,
            "critical" => SnykSeverity.Critical,
            _ => SnykSeverity.Unknown,
        };
    }
}
