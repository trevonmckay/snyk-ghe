namespace SnykGhe.Core.Snyk
{
    /// <summary>
    /// Runs <c>snyk code test</c> (SAST) and returns a normalized result for the Code Check Run.
    /// Reports the snapshot to the Snyk Web UI with <c>--report</c> when the context asks to publish.
    /// A repo with no scannable source, or an org without the Snyk Code entitlement, yields a
    /// not-applicable result so no Check Run is posted (rather than a failure).
    /// </summary>
    public sealed class CliCodeScanner : ICodeScanner
    {
        private readonly CliProductScanRunner _runner;

        public CliCodeScanner(CliProductScanRunner runner)
        {
            _runner = runner;
        }

        public Task<ProductScanResult> ScanAsync(ScanContext context, CancellationToken cancellationToken)
        {
            var args = new List<string> { "code", "test", "--json" };
            SnykCliRunner.AddOrgArg(args, context.Policy);

            if (context.Publish)
            {
                CliProductScanRunner.AddPublishArgs(args, context, "project-name");
            }

            return _runner.RunAsync(SnykProduct.Code, args, context, SnykCodeResult.Parse, cancellationToken);
        }
    }
}
