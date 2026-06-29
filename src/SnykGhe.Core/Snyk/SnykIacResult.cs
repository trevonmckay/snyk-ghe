using System.Text.Json;

namespace SnykGhe.Core.Snyk
{
    /// <summary>
    /// Parses <c>snyk iac test --json</c> output: a JSON array with one object per scanned file (a single
    /// object when only one file is scanned), each carrying an <c>infrastructureAsCodeIssues</c> array.
    /// Each issue has <c>severity</c>, <c>title</c>, and <c>lineNumber</c>; the file's path is <c>targetFile</c>.
    /// </summary>
    public static class SnykIacResult
    {
        public static ProductScanResult Parse(string json)
        {
            if (string.IsNullOrWhiteSpace(json))
            {
                return new ProductScanResult { Product = SnykProduct.Iac, Findings = [] };
            }

            try
            {
                using var doc = JsonDocument.Parse(json);
                List<JsonElement> files = doc.RootElement.ValueKind == JsonValueKind.Array
                    ? doc.RootElement.EnumerateArray().ToList()
                    : [doc.RootElement];

                var findings = new List<SnykFinding>();
                foreach (var file in files)
                {
                    var targetFile = GetString(file, "targetFile");
                    if (!file.TryGetProperty("infrastructureAsCodeIssues", out var issues) || issues.ValueKind != JsonValueKind.Array)
                    {
                        continue;
                    }

                    foreach (var issue in issues.EnumerateArray())
                    {
                        findings.Add(new SnykFinding
                        {
                            Severity = GetString(issue, "severity") ?? "low",
                            Title = GetString(issue, "title") is { Length: > 0 } title ? title : "IaC misconfiguration",
                            Location = IssueLocation(targetFile, issue),
                        });
                    }
                }

                return new ProductScanResult { Product = SnykProduct.Iac, Findings = findings };
            }
            catch (JsonException ex)
            {
                return ProductScanResult.Fail(SnykProduct.Iac, ex.Message);
            }
        }

        private static string? IssueLocation(string? targetFile, JsonElement issue)
        {
            if (string.IsNullOrEmpty(targetFile))
            {
                return null;
            }

            // Snyk reports lineNumber -1 when the line is unknown.
            return issue.TryGetProperty("lineNumber", out var line) && line.ValueKind == JsonValueKind.Number && line.GetInt32() > 0
                ? $"{targetFile}:{line.GetInt32()}"
                : targetFile;
        }

        private static string? GetString(JsonElement element, string property) =>
            element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
                ? value.GetString()
                : null;
    }
}
