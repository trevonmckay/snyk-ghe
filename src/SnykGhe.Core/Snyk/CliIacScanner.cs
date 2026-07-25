namespace SnykGhe.Core.Snyk
{
    /// <summary>
    /// Runs <c>snyk iac test</c> and returns a normalized result for the IaC Check Run. Reports to the
    /// Snyk Web UI with <c>--report</c> when the context asks to publish. A repo with no IaC files
    /// yields a not-applicable result so no Check Run is posted.
    /// </summary>
    public sealed class CliIacScanner : IIacScanner
    {
        private readonly CliProductScanRunner _runner;

        public CliIacScanner(CliProductScanRunner runner)
        {
            _runner = runner;
        }

        public Task<ProductScanResult> ScanAsync(ScanContext context, CancellationToken cancellationToken)
        {
            var args = new List<string> { "iac", "test", "--json" };
            SnykCliRunner.AddOrgArg(args, context.Policy);

            if (context.Publish)
            {
                // `snyk iac test --report` needs a target name to attach the snapshot to.
                CliProductScanRunner.AddPublishArgs(args, context, "target-name");
            }

            return _runner.RunAsync(SnykProduct.Iac, args, context, SnykIacResult.Parse, cancellationToken);
        }
    }
}
