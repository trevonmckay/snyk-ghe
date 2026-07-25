namespace SnykGhe.Core.Configuration
{
    /// <summary>How a given Snyk product is executed.</summary>
    public enum ScanEngine
    {
        /// <summary>Shell out to the Snyk CLI against the checked-out working copy.</summary>
        Cli,

        /// <summary>Call the Snyk Test REST API.</summary>
        Api,
    }

    /// <summary>
    /// Per-product engine selection, so a product whose API path misbehaves can be moved back to the CLI on
    /// its own without moving the others.
    /// </summary>
    public sealed class ScanEngineOptions
    {
        public ScanEngine OpenSource { get; set; } = ScanEngine.Cli;

        public ScanEngine Code { get; set; } = ScanEngine.Cli;

        /// <summary>
        /// Snyk's Test API exposes an <c>iac</c> scan configuration but no resource type that produces an IaC
        /// scan component, so a submitted IaC test always fails to assemble. Only <see cref="ScanEngine.Cli"/>
        /// is accepted; startup validation rejects the other value rather than letting every scan fail.
        /// </summary>
        public ScanEngine Iac { get; set; } = ScanEngine.Cli;
    }
}
