using System.Text.Json;

namespace SnykGhe.Core.Snyk
{
    /// <summary>
    /// Parses <c>snyk code test --json</c> output, which is SARIF 2.1.0. Snyk Code severity is taken from the
    /// SARIF result <c>level</c>: error → high, warning → medium, note/info → low. Snyk Code never reports
    /// critical. Parsing is defensive — a result missing a field is rendered with sane fallbacks rather than
    /// failing the whole scan.
    /// </summary>
    public static class SnykCodeResult
    {
        public static ProductScanResult Parse(string json)
        {
            if (string.IsNullOrWhiteSpace(json))
            {
                return new ProductScanResult { Product = SnykProduct.Code, Findings = [] };
            }

            try
            {
                using var doc = JsonDocument.Parse(json);
                var findings = new List<SnykFinding>();

                if (doc.RootElement.TryGetProperty("runs", out var runs) && runs.ValueKind == JsonValueKind.Array)
                {
                    foreach (var run in runs.EnumerateArray())
                    {
                        if (!run.TryGetProperty("results", out var results) || results.ValueKind != JsonValueKind.Array)
                        {
                            continue;
                        }

                        foreach (var result in results.EnumerateArray())
                        {
                            if (IsSuppressed(result))
                            {
                                continue;
                            }

                            var (filePath, startLine, endLine) = ResultLocation(result);
                            findings.Add(new SnykFinding
                            {
                                Severity = LevelToSeverity(GetString(result, "level")),
                                Title = ResultTitle(result),
                                Location = DisplayLocation(filePath, startLine),
                                FilePath = filePath,
                                StartLine = startLine,
                                EndLine = endLine,
                            });
                        }
                    }
                }

                // Retain the raw SARIF so it can be uploaded to GitHub code scanning verbatim.
                return new ProductScanResult { Product = SnykProduct.Code, Findings = findings, RawSarif = json };
            }
            catch (JsonException ex)
            {
                return ProductScanResult.Fail(SnykProduct.Code, ex.Message);
            }
        }

        private static string ResultTitle(JsonElement result)
        {
            if (result.TryGetProperty("message", out var message) && message.TryGetProperty("text", out var text)
                && text.GetString() is { Length: > 0 } t)
            {
                return t;
            }

            return GetString(result, "ruleId") is { Length: > 0 } ruleId ? ruleId : "Code issue";
        }

        /// <summary>
        /// Extracts the first physical location's repo-relative path and line region from a SARIF result.
        /// Returns nulls when the result carries no usable location (e.g. a project-wide finding).
        /// </summary>
        private static (string? FilePath, int? StartLine, int? EndLine) ResultLocation(JsonElement result)
        {
            if (!result.TryGetProperty("locations", out var locations) || locations.ValueKind != JsonValueKind.Array)
            {
                return (null, null, null);
            }

            foreach (var location in locations.EnumerateArray())
            {
                if (!location.TryGetProperty("physicalLocation", out var physical))
                {
                    continue;
                }

                var uri = physical.TryGetProperty("artifactLocation", out var artifact)
                    ? GetString(artifact, "uri")
                    : null;
                if (string.IsNullOrEmpty(uri))
                {
                    continue;
                }

                int? startLine = null;
                int? endLine = null;
                if (physical.TryGetProperty("region", out var region))
                {
                    startLine = GetInt(region, "startLine");
                    // SARIF omits endLine for a single-line region; fall back to startLine so an annotation
                    // always has a valid endLine >= startLine.
                    endLine = GetInt(region, "endLine") ?? startLine;
                }

                return (uri, startLine, endLine);
            }

            return (null, null, null);
        }

        /// <summary>Human-readable "file:line" (or just "file") for the summary table; null when there is no path.</summary>
        private static string? DisplayLocation(string? filePath, int? startLine) => filePath switch
        {
            null => null,
            _ when startLine is int line => $"{filePath}:{line}",
            _ => filePath,
        };

        /// <summary>
        /// True when a SARIF result carries a suppression that is in effect. Snyk Code emits ignores
        /// created in the Web UI (Consistent Ignores) as <c>suppressions</c> entries on the result rather
        /// than omitting the result — so a consumer that does not honor them re-reports ignored findings.
        /// A suppression applies unless its <c>status</c> is <c>underReview</c> or <c>rejected</c>; an
        /// absent status defaults to <c>accepted</c> per the SARIF 2.1.0 spec.
        /// </summary>
        private static bool IsSuppressed(JsonElement result)
        {
            if (!result.TryGetProperty("suppressions", out var suppressions)
                || suppressions.ValueKind != JsonValueKind.Array)
            {
                return false;
            }

            foreach (var suppression in suppressions.EnumerateArray())
            {
                var status = GetString(suppression, "status");
                if (status is null || status.Equals("accepted", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        private static string? GetString(JsonElement element, string property) =>
            element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
                ? value.GetString()
                : null;

        private static int? GetInt(JsonElement element, string property) =>
            element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.Number
                && value.TryGetInt32(out var i)
                ? i
                : null;

        private static string LevelToSeverity(string? level) => level?.ToLowerInvariant() switch
        {
            "error" => "high",
            "warning" => "medium",
            "note" => "low",
            "info" => "low",
            _ => "low",
        };
    }
}
