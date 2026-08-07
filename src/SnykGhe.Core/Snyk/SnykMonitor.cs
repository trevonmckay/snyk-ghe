using Microsoft.Extensions.Options;
using SnykGhe.Core.Configuration;

namespace SnykGhe.Core.Snyk
{
    /// <summary>
    /// Persists a scan to the Snyk Web UI with <c>snyk monitor</c>. Monitoring publishes a durable snapshot
    /// that Snyk alerts against as new vulnerabilities are disclosed; it is a separate concern from testing a
    /// revision, and always runs through the CLI regardless of which engine performed the scan.
    /// </summary>
    public sealed class SnykMonitor
    {
        private readonly SnykCliRunner _cli;
        private readonly SnykOptions _options;
        private readonly ILogger<SnykMonitor> _logger;

        public SnykMonitor(SnykCliRunner cli, IOptions<SnykOptions> options, ILogger<SnykMonitor> logger)
        {
            _cli = cli;
            _options = options.Value;
            _logger = logger;
        }

        /// <summary>
        /// Publishes the snapshot and returns the URL the Check Run links to, or null when monitoring is
        /// disabled or the CLI produced no usable URL. A monitor failure is non-fatal: the gating test result
        /// already drives the check, so this only costs the deep link. Must run after the Open Source scan in
        /// the same directory — it relies on the dependency restore that scan performed and does not repeat it.
        /// </summary>
        public async Task<string?> MonitorAsync(ScanContext context, bool forceMonitor, CancellationToken cancellationToken)
        {
            // The default-branch baseline forces monitoring; the per-PR-branch path only monitors when the
            // Snyk:Monitor opt-in is set.
            if (!forceMonitor && !_options.Monitor)
            {
                return null;
            }

            var args = new List<string> { "monitor", "--json", "--all-projects" };
            SnykCliRunner.AddNuGetNamingArgs(args, context.Policy);
            SnykCliRunner.AddOrgArg(args, context.Policy);
            SnykCliRunner.AddExcludeArgs(args, context.Policy);

            if (!string.IsNullOrWhiteSpace(context.RemoteRepoUrl))
            {
                args.Add($"--remote-repo-url={context.RemoteRepoUrl}");
            }

            if (!string.IsNullOrWhiteSpace(context.TargetReference))
            {
                args.Add($"--target-reference={context.TargetReference}");
            }

            SnykCliOutcome outcome;
            try
            {
                outcome = await _cli.RunAsync(
                    args,
                    context.WorkingDirectory,
                    cancellationToken,
                    applyTimeout: true,
                    timeoutSecondsOverride: _options.MonitorTimeoutSeconds);
            }
            catch (ScanInterruptedException)
            {
                // Host is shutting down mid-monitor: not a monitor failure to swallow. Let it propagate so the
                // delivery is redelivered and the whole scan re-runs on a healthy replica.
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Snyk monitor failed in {Dir}; check will have no Snyk link.", context.WorkingDirectory);
                return null;
            }

            if (outcome.AuthenticationFailed)
            {
                _logger.LogWarning("Could not obtain a Snyk OAuth token for monitor; check will have no Snyk link.");
                return null;
            }

            if (outcome.TimedOut)
            {
                _logger.LogWarning(
                    "Snyk monitor timed out after {Seconds}s in {Dir}; check will have no Snyk link.",
                    _options.MonitorTimeoutSeconds, context.WorkingDirectory);
                return null;
            }

            // A non-zero exit still prints uris for the manifests that did monitor, so parse regardless.
            if (outcome.ExitCode != 0)
            {
                // Under --all-projects a non-zero exit is usually a partial failure: some manifests monitored,
                // one errored. The per-manifest error is in the --json stdout, not stderr, so surface it there.
                var failures = SnykMonitorResult.Failures(outcome.StandardOutput);
                if (failures.Count > 0)
                {
                    _logger.LogWarning("Snyk monitor exited {Code} in {Dir}: {Count} manifest(s) failed to monitor.",
                        outcome.ExitCode, context.WorkingDirectory, failures.Count);
                    foreach (var failure in failures)
                    {
                        _logger.LogWarning("Snyk monitor could not monitor {Manifest}: {Error}",
                            failure.Manifest ?? "(unknown manifest)", (failure.Error ?? string.Empty).Trim());
                    }
                }
                else
                {
                    _logger.LogWarning("Snyk monitor exited {Code} in {Dir}: {Error}",
                        outcome.ExitCode, context.WorkingDirectory, outcome.StandardError.Trim());
                }
            }

            return SnykMonitorResult.FirstUri(outcome.StandardOutput);
        }
    }
}
