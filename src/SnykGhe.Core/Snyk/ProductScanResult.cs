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

        /// <summary>Repo-relative source path (Code only); null for Open Source. Drives Check Run annotations.</summary>
        public string? FilePath { get; init; }

        /// <summary>First line of the finding's region (Code only); pairs with <see cref="FilePath"/> for annotations.</summary>
        public int? StartLine { get; init; }

        /// <summary>Last line of the finding's region (Code only); equals <see cref="StartLine"/> for a single-line region.</summary>
        public int? EndLine { get; init; }

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

        /// <summary>
        /// Raw SARIF 2.1.0 payload from <c>snyk code test --json</c> (Code only; null otherwise). Retained
        /// verbatim so it can be uploaded to GitHub code scanning — kept unfiltered because GitHub honors the
        /// SARIF <c>suppressions</c> field, unlike the gate counts which drop accepted ignores.
        /// </summary>
        public string? RawSarif { get; init; }

        public int CountBySeverity(SnykSeverity severity) =>
            Findings.Count(f => SnykSeverityExtensions.Parse(f.Severity) == severity);

        public int CountAtOrAbove(SnykSeverity threshold) =>
            Findings.Count(f => SnykSeverityExtensions.Parse(f.Severity) >= threshold);

        /// <summary>Returns a copy with <see cref="DetailsUrl"/> set, used to attach the Snyk Web UI link
        /// after a product has published its snapshot.</summary>
        public ProductScanResult WithDetailsUrl(string detailsUrl) =>
            new()
            {
                Product = Product,
                Findings = Findings,
                Failed = Failed,
                NotApplicable = NotApplicable,
                FailureMessage = FailureMessage,
                DetailsUrl = detailsUrl,
                RawSarif = RawSarif,
            };

        public static ProductScanResult Skip(SnykProduct product) =>
            new() { Product = product, Findings = [], NotApplicable = true };

        public static ProductScanResult Fail(SnykProduct product, string message) =>
            new() { Product = product, Findings = [], Failed = true, FailureMessage = message };
    }
}
