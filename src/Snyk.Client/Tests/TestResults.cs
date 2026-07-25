using System.Text.Json;

namespace Snyk.Client.Tests
{
    /// <summary>Terminal and in-flight states of a test's execution.</summary>
    public enum TestExecutionState
    {
        Unknown,
        InProgress,
        Finished,
        Errored,
        Canceled,
    }

    /// <summary>An error reported against a test that did not complete.</summary>
    public sealed class SnykTestError
    {
        public string? Code { get; init; }

        public string? Detail { get; init; }

        public override string ToString() =>
            string.IsNullOrWhiteSpace(Code) ? Detail ?? "Unknown error." : $"{Code}: {Detail}";
    }

    /// <summary>A single package in a dependency path.</summary>
    public sealed class SnykPackageRef
    {
        public required string Name { get; init; }

        public required string Version { get; init; }

        public override string ToString() => $"{Name}@{Version}";
    }

    /// <summary>
    /// Remediation advice attached to a finding. <see cref="UpgradePath"/> mirrors the dependency path with
    /// the versions that resolve the issue, so its last element is the fixed direct dependency.
    /// </summary>
    public sealed class SnykFix
    {
        /// <summary>e.g. <c>upgrade_package_advice</c>.</summary>
        public string? Format { get; init; }

        public string? PackageName { get; init; }

        /// <summary>True when Snyk considers the finding fully resolved by the advised action.</summary>
        public bool FullyResolved { get; init; }

        public IReadOnlyList<SnykPackageRef> UpgradePath { get; init; } = [];

        /// <summary>True when the advice is an upgrade with a usable path.</summary>
        public bool IsUpgradable =>
            string.Equals(Format, "upgrade_package_advice", StringComparison.OrdinalIgnoreCase)
            && UpgradePath.Count >= 2;
    }

    /// <summary>A security problem underlying a finding (a Snyk vuln, a CWE, a license rule).</summary>
    public sealed class SnykProblem
    {
        public required string Id { get; init; }

        public string? Source { get; init; }

        public bool IsFixable { get; init; }

        public IReadOnlyList<string> InitiallyFixedInVersions { get; init; } = [];
    }

    /// <summary>A single finding produced by a test, normalized across scanners.</summary>
    public sealed class SnykTestFinding
    {
        public required string Key { get; init; }

        public required string Title { get; init; }

        /// <summary>critical | high | medium | low | none | other.</summary>
        public required string Severity { get; init; }

        /// <summary>Which scanner produced it: <c>sca</c>, <c>sast</c>, <c>iac</c>, <c>secrets</c>, …</summary>
        public string? FindingType { get; init; }

        /// <summary>Package the finding is located in, for SCA findings.</summary>
        public SnykPackageRef? Package { get; init; }

        /// <summary>Source file path, for SAST/IaC/secrets findings.</summary>
        public string? FilePath { get; init; }

        public int? StartLine { get; init; }

        /// <summary>Dependency path from the root project to the vulnerable package, for SCA findings.</summary>
        public IReadOnlyList<SnykPackageRef> DependencyPath { get; init; } = [];

        public IReadOnlyList<SnykProblem> Problems { get; init; } = [];

        public SnykFix? Fix { get; init; }

        /// <summary>Versions that resolve the finding, gathered from its problems.</summary>
        public IReadOnlyList<string> FixedInVersions =>
            Problems.SelectMany(p => p.InitiallyFixedInVersions).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    /// <summary>Counts of findings by severity, as computed by Snyk.</summary>
    public sealed class SnykTestSummary
    {
        public int Total { get; init; }

        public int Critical { get; init; }

        public int High { get; init; }

        public int Medium { get; init; }

        public int Low { get; init; }
    }

    /// <summary>A completed (or failed) test resource.</summary>
    public sealed class SnykTest
    {
        public required string Id { get; init; }

        /// <summary>
        /// The <c>snyk-request-id</c> of the response this test was read from. A test that reached a terminal
        /// error state is not an HTTP failure, so this is the handle to give Snyk support to trace it.
        /// </summary>
        public string? RequestId { get; init; }

        public TestExecutionState Execution { get; init; }

        /// <summary><c>pass</c> or <c>fail</c>, absent when the test errored.</summary>
        public string? Outcome { get; init; }

        public string? OutcomeReason { get; init; }

        public SnykTestSummary Summary { get; init; } = new();

        public IReadOnlyList<SnykTestError> Errors { get; init; } = [];

        public bool Succeeded => Execution == TestExecutionState.Finished;

        /// <summary>Joined error details, for surfacing why a test did not complete.</summary>
        public string ErrorSummary => Errors.Count == 0
            ? "The Snyk test did not complete."
            : string.Join("; ", Errors.Select(e => e.ToString()));
    }

    /// <summary>A completed test together with its findings.</summary>
    public sealed class SnykTestRun
    {
        public required SnykTest Test { get; init; }

        public required IReadOnlyList<SnykTestFinding> Findings { get; init; }
    }

    /// <summary>Parsers translating JSON:API payloads into the public result model.</summary>
    internal static class TestResultParser
    {
        internal static SnykTest ParseTest(JsonElement data, string? requestId = null)
        {
            var attributes = data.GetProperty("attributes");

            return new SnykTest
            {
                Id = data.GetProperty("id").GetString() ?? string.Empty,
                RequestId = requestId,
                Execution = ParseExecution(Str(attributes, "state", "execution")),
                Outcome = Str(attributes, "outcome", "result"),
                OutcomeReason = Str(attributes, "outcome", "reason"),
                Summary = ParseSummary(attributes),
                Errors = ParseErrors(attributes),
            };
        }

        private static TestExecutionState ParseExecution(string? value) => value?.ToLowerInvariant() switch
        {
            "finished" => TestExecutionState.Finished,
            "errored" => TestExecutionState.Errored,
            "canceled" or "cancelled" => TestExecutionState.Canceled,
            "in_progress" or "started" or "pending" => TestExecutionState.InProgress,
            _ => TestExecutionState.Unknown,
        };

        private static SnykTestSummary ParseSummary(JsonElement attributes)
        {
            if (!attributes.TryGetProperty("effective_summary", out var summary) || summary.ValueKind != JsonValueKind.Object)
            {
                return new SnykTestSummary();
            }

            var total = summary.TryGetProperty("count", out var c) && c.ValueKind == JsonValueKind.Number ? c.GetInt32() : 0;

            if (!summary.TryGetProperty("count_by", out var countBy)
                || !countBy.TryGetProperty("severity", out var bySeverity)
                || bySeverity.ValueKind != JsonValueKind.Object)
            {
                return new SnykTestSummary { Total = total };
            }

            int Sev(string name) =>
                bySeverity.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number ? v.GetInt32() : 0;

            return new SnykTestSummary
            {
                Total = total,
                Critical = Sev("critical"),
                High = Sev("high"),
                Medium = Sev("medium"),
                Low = Sev("low"),
            };
        }

        private static List<SnykTestError> ParseErrors(JsonElement attributes)
        {
            var errors = new List<SnykTestError>();

            if (!attributes.TryGetProperty("state", out var state) || !state.TryGetProperty("errors", out var list))
            {
                return errors;
            }

            // A single error is emitted as an object; several as an array.
            if (list.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in list.EnumerateArray())
                {
                    errors.Add(ParseError(item));
                }
            }
            else if (list.ValueKind == JsonValueKind.Object)
            {
                errors.Add(ParseError(list));
            }

            return errors;
        }

        private static SnykTestError ParseError(JsonElement element) => new()
        {
            Code = Str(element, "code"),
            Detail = Str(element, "detail"),
        };

        internal static SnykTestFinding ParseFinding(JsonElement data)
        {
            var attributes = data.GetProperty("attributes");

            return new SnykTestFinding
            {
                Key = Str(attributes, "key") ?? Str(data, "id") ?? string.Empty,
                Title = Str(attributes, "title") ?? string.Empty,
                Severity = Str(attributes, "rating", "severity") ?? "unknown",
                FindingType = Str(attributes, "finding_type"),
                Package = ParsePackageLocation(attributes),
                FilePath = ParseSourceLocation(attributes, out var startLine),
                StartLine = startLine,
                DependencyPath = ParseDependencyPath(attributes),
                Problems = ParseProblems(attributes),
                Fix = ParseFix(data),
            };
        }

        private static SnykPackageRef? ParsePackageLocation(JsonElement attributes)
        {
            if (!attributes.TryGetProperty("locations", out var locations) || locations.ValueKind != JsonValueKind.Array)
            {
                return null;
            }

            foreach (var location in locations.EnumerateArray())
            {
                if (location.TryGetProperty("package", out var package))
                {
                    return ParsePackage(package);
                }
            }

            return null;
        }

        private static string? ParseSourceLocation(JsonElement attributes, out int? startLine)
        {
            startLine = null;

            if (!attributes.TryGetProperty("locations", out var locations) || locations.ValueKind != JsonValueKind.Array)
            {
                return null;
            }

            foreach (var location in locations.EnumerateArray())
            {
                if (!location.TryGetProperty("source_location", out var source))
                {
                    continue;
                }

                if (source.TryGetProperty("start_line", out var line) && line.ValueKind == JsonValueKind.Number)
                {
                    startLine = line.GetInt32();
                }

                return Str(source, "file");
            }

            return null;
        }

        private static List<SnykPackageRef> ParseDependencyPath(JsonElement attributes)
        {
            var path = new List<SnykPackageRef>();

            if (!attributes.TryGetProperty("evidence", out var evidence) || evidence.ValueKind != JsonValueKind.Array)
            {
                return path;
            }

            foreach (var item in evidence.EnumerateArray())
            {
                if (!string.Equals(Str(item, "source"), "dependency_path", StringComparison.OrdinalIgnoreCase)
                    || !item.TryGetProperty("path", out var pathElement)
                    || pathElement.ValueKind != JsonValueKind.Array)
                {
                    continue;
                }

                foreach (var node in pathElement.EnumerateArray())
                {
                    var package = ParsePackage(node);
                    if (package is not null)
                    {
                        path.Add(package);
                    }
                }

                break;
            }

            return path;
        }

        private static List<SnykProblem> ParseProblems(JsonElement attributes)
        {
            var problems = new List<SnykProblem>();

            if (!attributes.TryGetProperty("problems", out var list) || list.ValueKind != JsonValueKind.Array)
            {
                return problems;
            }

            foreach (var item in list.EnumerateArray())
            {
                var id = Str(item, "id");
                if (string.IsNullOrWhiteSpace(id))
                {
                    continue;
                }

                problems.Add(new SnykProblem
                {
                    Id = id,
                    Source = Str(item, "source"),
                    IsFixable = item.TryGetProperty("is_fixable", out var f) && f.ValueKind == JsonValueKind.True,
                    InitiallyFixedInVersions = StringArray(item, "initially_fixed_in_versions"),
                });
            }

            return problems;
        }

        private static SnykFix? ParseFix(JsonElement data)
        {
            if (!data.TryGetProperty("relationships", out var relationships)
                || !relationships.TryGetProperty("fix", out var fix)
                || !fix.TryGetProperty("data", out var fixData)
                || !fixData.TryGetProperty("attributes", out var attributes))
            {
                return null;
            }

            if (!attributes.TryGetProperty("action", out var action))
            {
                return null;
            }

            var upgradePath = new List<SnykPackageRef>();
            if (action.TryGetProperty("upgrade_paths", out var paths) && paths.ValueKind == JsonValueKind.Array)
            {
                foreach (var candidate in paths.EnumerateArray())
                {
                    if (!candidate.TryGetProperty("dependency_path", out var dependencyPath)
                        || dependencyPath.ValueKind != JsonValueKind.Array)
                    {
                        continue;
                    }

                    // A drop advises removing the package rather than upgrading it; it carries no usable version.
                    if (candidate.TryGetProperty("is_drop", out var isDrop) && isDrop.ValueKind == JsonValueKind.True)
                    {
                        continue;
                    }

                    foreach (var node in dependencyPath.EnumerateArray())
                    {
                        var package = ParsePackage(node);
                        if (package is not null)
                        {
                            upgradePath.Add(package);
                        }
                    }

                    break;
                }
            }

            return new SnykFix
            {
                Format = Str(action, "format"),
                PackageName = Str(action, "package_name"),
                FullyResolved = string.Equals(Str(attributes, "outcome"), "fully_resolved", StringComparison.OrdinalIgnoreCase),
                UpgradePath = upgradePath,
            };
        }

        private static SnykPackageRef? ParsePackage(JsonElement element)
        {
            var name = Str(element, "name");
            var version = Str(element, "version");

            return string.IsNullOrWhiteSpace(name)
                ? null
                : new SnykPackageRef { Name = name, Version = version ?? string.Empty };
        }

        private static List<string> StringArray(JsonElement element, string property)
        {
            var values = new List<string>();

            if (!element.TryGetProperty(property, out var array) || array.ValueKind != JsonValueKind.Array)
            {
                return values;
            }

            foreach (var item in array.EnumerateArray())
            {
                if (item.ValueKind == JsonValueKind.String)
                {
                    var value = item.GetString();
                    if (!string.IsNullOrWhiteSpace(value))
                    {
                        values.Add(value);
                    }
                }
            }

            return values;
        }

        /// <summary>Reads a string property, optionally nested one level, returning null when absent.</summary>
        private static string? Str(JsonElement element, string property, string? nested = null)
        {
            if (!element.TryGetProperty(property, out var value))
            {
                return null;
            }

            if (nested is not null)
            {
                if (value.ValueKind != JsonValueKind.Object || !value.TryGetProperty(nested, out value))
                {
                    return null;
                }
            }

            return value.ValueKind == JsonValueKind.String ? value.GetString() : null;
        }
    }
}
