namespace SnykGhe.Core.Snyk
{
    /// <summary>
    /// Runs <c>snyk test</c> against a checked-out working directory and parses the result.
    /// Authentication is global; org targeting and severity come from the per-scan policy.
    /// </summary>
    public sealed class CliOpenSourceScanner : IOpenSourceScanner
    {
        private readonly SnykCliRunner _cli;
        private readonly ILogger<CliOpenSourceScanner> _logger;

        public CliOpenSourceScanner(SnykCliRunner cli, ILogger<CliOpenSourceScanner> logger)
        {
            _cli = cli;
            _logger = logger;
        }

        public async Task<SnykScanResult> ScanAsync(ScanContext context, CancellationToken cancellationToken)
        {
            await _cli.RestoreDependenciesAsync(context.WorkingDirectory, context.Policy.Ecosystem, cancellationToken);

            // Report every severity; the gate threshold is applied in our own code (CountAtOrAbove) so the
            // summary shows the full breakdown. Passing --severity-threshold would drop lower-severity issues
            // from the JSON, under-reporting counts relative to the monitor snapshot the check links to.
            var args = new List<string> { "test", "--json", "--all-projects" };
            SnykCliRunner.AddNuGetNamingArgs(args, context.Policy);
            SnykCliRunner.AddOrgArg(args, context.Policy);

            var outcome = await _cli.RunAsync(args, context.WorkingDirectory, cancellationToken);

            if (outcome.AuthenticationFailed)
            {
                return Failed("Snyk OAuth authentication failed.");
            }

            if (outcome.TimedOut)
            {
                return Failed("Snyk scan timed out.");
            }

            // Exit codes: 0 = no vulns, 1 = vulns found, 2 = CLI/usage error, 3 = no supported manifests.
            if (outcome.ExitCode >= 2)
            {
                var message = string.IsNullOrWhiteSpace(outcome.StandardError)
                    ? $"Snyk CLI exited with code {outcome.ExitCode}."
                    : outcome.StandardError.Trim();
                _logger.LogWarning("Snyk CLI error (exit {Code}): {Error}", outcome.ExitCode, message);
                return Failed(message);
            }

            return SnykScanResult.Parse(outcome.StandardOutput);
        }

        private static SnykScanResult Failed(string message) =>
            new() { Projects = [], Failed = true, FailureMessage = message };
    }
}
