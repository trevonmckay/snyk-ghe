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

                            findings.Add(new SnykFinding
                            {
                                Severity = LevelToSeverity(GetString(result, "level")),
                                Title = ResultTitle(result),
                                Location = ResultLocation(result),
                            });
                        }
                    }
                }

                return new ProductScanResult { Product = SnykProduct.Code, Findings = findings };
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

        private static string? ResultLocation(JsonElement result)
        {
            if (!result.TryGetProperty("locations", out var locations) || locations.ValueKind != JsonValueKind.Array)
            {
                return null;
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

                if (physical.TryGetProperty("region", out var region)
                    && region.TryGetProperty("startLine", out var line) && line.ValueKind == JsonValueKind.Number)
                {
                    return $"{uri}:{line.GetInt32()}";
                }

                return uri;
            }

            return null;
        }

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
