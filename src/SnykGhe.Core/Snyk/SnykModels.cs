using System.Text.Json;
using System.Text.Json.Serialization;

namespace SnykGhe.Core.Snyk
{
    /// <summary>A single vulnerability from `snyk test --json`.</summary>
    public sealed class SnykVulnerability
    {
        [JsonPropertyName("id")] public string Id { get; set; } = string.Empty;
        [JsonPropertyName("title")] public string Title { get; set; } = string.Empty;
        [JsonPropertyName("severity")] public string Severity { get; set; } = string.Empty;

        /// <summary>"vuln" for a security vulnerability, "license" for a license-policy issue.</summary>
        [JsonPropertyName("type")] public string? Type { get; set; }

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

    /// <summary>
    /// A single project entry from `snyk monitor --json`. The CLI emits one object per monitored manifest
    /// (a JSON array under --all-projects); each carries the <c>uri</c> of the snapshot on the Snyk Web UI.
    /// </summary>
    public sealed class SnykMonitorResult
    {
        [JsonPropertyName("uri")] public string? Uri { get; set; }

        [JsonPropertyName("ok")] public bool? Ok { get; set; }

        [JsonPropertyName("error")] public string? Error { get; set; }

        [JsonPropertyName("path")] public string? Path { get; set; }

        [JsonPropertyName("targetFile")] public string? TargetFile { get; set; }

        [JsonPropertyName("displayTargetFile")] public string? DisplayTargetFile { get; set; }

        /// <summary>The manifest a result refers to, preferring the friendliest identifier the CLI supplied.</summary>
        public string? Manifest => DisplayTargetFile ?? TargetFile ?? Path;

        /// <summary>
        /// Returns the first snapshot URL from `snyk monitor --json` output (object for one manifest, array
        /// under --all-projects), or null when the output is empty, unparseable, or carries no uri.
        /// </summary>
        public static string? FirstUri(string json) =>
            Parse(json).FirstOrDefault(r => !string.IsNullOrWhiteSpace(r.Uri))?.Uri;

        /// <summary>
        /// Returns the manifests that failed to monitor (<c>ok:false</c>) from `snyk monitor --json` output.
        /// Under --all-projects a non-zero exit is usually a partial failure — some manifests monitored, one
        /// errored — and the error text lives here in stdout rather than stderr.
        /// </summary>
        public static IReadOnlyList<SnykMonitorResult> Failures(string json) =>
            Parse(json).Where(r => r.Ok == false).ToList();

        /// <summary>Parses monitor output (single object or --all-projects array) into results, skipping
        /// any element that will not deserialize so one malformed entry does not discard the rest.</summary>
        private static IReadOnlyList<SnykMonitorResult> Parse(string json)
        {
            if (string.IsNullOrWhiteSpace(json))
            {
                return [];
            }

            try
            {
                using var doc = JsonDocument.Parse(json);
                var elements = new List<JsonElement>();
                if (doc.RootElement.ValueKind == JsonValueKind.Array)
                {
                    elements.AddRange(doc.RootElement.EnumerateArray());
                }
                else
                {
                    elements.Add(doc.RootElement);
                }

                var results = new List<SnykMonitorResult>(elements.Count);
                foreach (var element in elements)
                {
                    try
                    {
                        if (element.Deserialize<SnykMonitorResult>() is { } result)
                        {
                            results.Add(result);
                        }
                    }
                    catch (JsonException)
                    {
                        // A single unparseable entry (e.g. a non-string error object) must not lose the others.
                    }
                }

                return results;
            }
            catch (JsonException)
            {
                return [];
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
