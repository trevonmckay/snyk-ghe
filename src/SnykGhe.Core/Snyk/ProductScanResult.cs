namespace SnykGhe.Core.Snyk
{
    /// <summary>The three Snyk products this app can run against a pull request, each its own Check Run.</summary>
    public enum SnykProduct
    {
        OpenSource,
        Code,
        Iac,
    }

    /// <summary>A single security finding, normalized across Snyk products so one Check Run builder renders any of them.</summary>
    public sealed class SnykFinding
    {
        /// <summary>low | medium | high | critical (Snyk Code never reports critical).</summary>
        public required string Severity { get; init; }

        public required string Title { get; init; }

        /// <summary>Where the finding lives: "package@version" (Open Source) or "file:line" (Code / IaC).</summary>
        public string? Location { get; init; }

        /// <summary>Open Source issue type — "vuln" or "license" — used to split the summary table; null otherwise.</summary>
        public string? IssueType { get; init; }

        /// <summary>Versions the issue is fixed in (Open Source only).</summary>
        public IReadOnlyList<string>? FixedIn { get; init; }
    }

    /// <summary>
    /// Outcome of one product scan, normalized for Check Run rendering. <see cref="NotApplicable"/> means
    /// there was nothing to scan or the product is not enabled for the org (no Check Run is posted), which
    /// is distinct from <see cref="Failed"/> (a tooling error surfaced as a neutral, non-blocking check).
    /// </summary>
    public sealed class ProductScanResult
    {
        public required SnykProduct Product { get; init; }

        public required IReadOnlyList<SnykFinding> Findings { get; init; }

        public bool Failed { get; init; }

        public bool NotApplicable { get; init; }

        public string? FailureMessage { get; init; }

        /// <summary>Snyk Web UI link for this product's published scan, when monitoring/reporting is enabled.</summary>
        public string? DetailsUrl { get; init; }

        public int CountBySeverity(SnykSeverity severity) =>
            Findings.Count(f => SnykSeverityExtensions.Parse(f.Severity) == severity);

        public int CountAtOrAbove(SnykSeverity threshold) =>
            Findings.Count(f => SnykSeverityExtensions.Parse(f.Severity) >= threshold);

        public static ProductScanResult Skip(SnykProduct product) =>
            new() { Product = product, Findings = [], NotApplicable = true };

        public static ProductScanResult Fail(SnykProduct product, string message) =>
            new() { Product = product, Findings = [], Failed = true, FailureMessage = message };
    }
}
