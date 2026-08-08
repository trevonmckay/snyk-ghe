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
            SnykCliRunner.AddExcludeArgs(args, context.Policy);

            var outcome = await _cli.RunAsync(args, context.WorkingDirectory, cancellationToken);
            var result = InterpretOutcome(outcome);

            if (result.NotApplicable)
            {
                _logger.LogInformation("Snyk Open Source found no supported manifests to scan; marking not applicable.");
            }
            else if (result.Failed)
            {
                _logger.LogWarning("Snyk Open Source scan did not complete: {Error}", result.FailureMessage);
            }

            return result;
        }

        /// <summary>
        /// Maps a raw Snyk CLI outcome to a scan result. Pure (no I/O or logging) so the exit-code policy is
        /// unit-testable without the CLI — in particular that exit 3 ("no supported manifests") is a skip, not
        /// the failure that exit 2 (a real CLI/usage error) produces.
        /// </summary>
        internal static SnykScanResult InterpretOutcome(SnykCliOutcome outcome)
        {
            if (outcome.AuthenticationFailed)
            {
                return Failed("Snyk OAuth authentication failed.");
            }

            if (outcome.TimedOut)
            {
                return Failed("Snyk scan timed out.");
            }

            // The Snyk CLI documents exactly four exit codes. Exit 3 ("no supported manifests") means there is
            // nothing for Open Source to scan (e.g. an infra-only repo), so it is a skip, not the failure that
            // exit 2 (a real CLI/usage error) produces. Any undocumented code falls through to a failure so an
            // unexpected outcome is surfaced rather than silently treated as a clean scan.
            return outcome.ExitCode switch
            {
                0 or 1 => SnykScanResult.Parse(outcome.StandardOutput), // 0 = no vulns, 1 = vulns found
                3 => NotApplicable(),                                   // no supported manifests — nothing to scan
                _ => Failed(string.IsNullOrWhiteSpace(outcome.StandardError) // 2 = CLI/usage error (or anything unexpected)
                    ? $"Snyk CLI exited with code {outcome.ExitCode}."
                    : outcome.StandardError.Trim()),
            };
        }

        private static SnykScanResult Failed(string message) =>
            new() { Projects = [], Failed = true, FailureMessage = message };

        private static SnykScanResult NotApplicable() =>
            new() { Projects = [], NotApplicable = true };
    }
}
