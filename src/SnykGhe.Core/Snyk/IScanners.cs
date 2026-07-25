using SnykGhe.Core.Configuration;

namespace SnykGhe.Core.Snyk
{
    /// <summary>
    /// Everything a scanner may need to scan one revision of one repository. A given implementation uses a
    /// subset: the CLI scanners read the working copy, while the API scanners identify the revision to Snyk
    /// by repository URL and reference instead.
    /// </summary>
    public sealed class ScanContext
    {
        /// <summary>Path to the checked-out working copy.</summary>
        public required string WorkingDirectory { get; init; }

        public required ResolvedPolicy Policy { get; init; }

        /// <summary>Canonical https URL of the repository on GitHub.</summary>
        public required string RemoteRepoUrl { get; init; }

        /// <summary>Branch (or other reference) being scanned.</summary>
        public required string TargetReference { get; init; }

        /// <summary>"owner/repo", used to name the project a published snapshot attaches to.</summary>
        public required string ProjectName { get; init; }

        /// <summary>Publish the scan's findings to the Snyk Web UI so the check can deep-link to them.</summary>
        public bool Publish { get; init; }
    }

    /// <summary>
    /// Scans a repository's dependencies (Snyk Open Source / SCA). Returns the raw Snyk shape rather than a
    /// normalized <see cref="ProductScanResult"/> because the fix-PR planner reads per-vulnerability upgrade
    /// paths that the normalized form discards.
    /// </summary>
    public interface IOpenSourceScanner
    {
        Task<SnykScanResult> ScanAsync(ScanContext context, CancellationToken cancellationToken);
    }

    /// <summary>Scans a repository's source for code vulnerabilities (Snyk Code / SAST).</summary>
    public interface ICodeScanner
    {
        Task<ProductScanResult> ScanAsync(ScanContext context, CancellationToken cancellationToken);
    }

    /// <summary>Scans a repository's infrastructure-as-code definitions (Snyk IaC).</summary>
    public interface IIacScanner
    {
        Task<ProductScanResult> ScanAsync(ScanContext context, CancellationToken cancellationToken);
    }
}
