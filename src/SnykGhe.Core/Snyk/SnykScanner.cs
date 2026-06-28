using CliWrap;
using CliWrap.Buffered;
using Microsoft.Extensions.Options;
using SnykGhe.Core.Configuration;

namespace SnykGhe.Core.Snyk
{
    /// <summary>
    /// Runs the Snyk CLI against a checked-out working directory and parses the result.
    /// Authentication is global; org targeting and severity come from the per-scan policy.
    /// </summary>
    public sealed class SnykScanner
    {
        private readonly SnykOptions _options;
        private readonly ILogger _logger;

        public SnykScanner(IOptions<SnykOptions> options, ILogger<SnykScanner> logger)
        {
            _options = options.Value;
            _logger = logger;
        }

        public async Task<SnykScanResult> ScanAsync(
            string workingDirectory,
            ResolvedPolicy policy,
            CancellationToken cancellationToken)
        {
            await RestoreDependenciesAsync(workingDirectory, policy.Ecosystem, cancellationToken);

            var args = new List<string> { "test", "--json", "--all-projects" };

            if (!string.IsNullOrWhiteSpace(policy.SeverityThreshold))
            {
                args.Add($"--severity-threshold={policy.SeverityThreshold}");
            }

            if (!string.IsNullOrWhiteSpace(policy.SnykOrgId))
            {
                args.Add($"--org={policy.SnykOrgId}");
            }

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(_options.ScanTimeoutSeconds));

            BufferedCommandResult result;
            try
            {
                result = await Cli.Wrap(_options.CliPath)
                    .WithArguments(args)
                    .WithWorkingDirectory(workingDirectory)
                    .WithEnvironmentVariables(BuildEnvironment())
                    // Snyk exits 1 when vulnerabilities are found — that is a successful scan, not a failure.
                    .WithValidation(CommandResultValidation.None)
                    .ExecuteBufferedAsync(timeout.Token);
            }
            catch (OperationCanceledException) when (timeout.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
            {
                _logger.LogWarning("Snyk scan timed out after {Seconds}s in {Dir}", _options.ScanTimeoutSeconds, workingDirectory);
                return new SnykScanResult { Projects = [], Failed = true, FailureMessage = "Snyk scan timed out." };
            }

            // Exit codes: 0 = no vulns, 1 = vulns found, 2 = CLI/usage error, 3 = no supported manifests.
            if (result.ExitCode >= 2)
            {
                var message = string.IsNullOrWhiteSpace(result.StandardError)
                    ? $"Snyk CLI exited with code {result.ExitCode}."
                    : result.StandardError.Trim();
                _logger.LogWarning("Snyk CLI error (exit {Code}): {Error}", result.ExitCode, message);
                return new SnykScanResult { Projects = [], Failed = true, FailureMessage = message };
            }

            return SnykScanResult.Parse(result.StandardOutput);
        }

        /// <summary>
        /// Restores dependencies so Snyk can resolve the full graph. NuGet in particular requires
        /// `dotnet restore` (project.assets.json) before `snyk test`. Best-effort: a restore failure is
        /// logged and the scan proceeds, since Snyk may still report on the manifests.
        /// </summary>
        private async Task RestoreDependenciesAsync(string workingDirectory, string ecosystem, CancellationToken cancellationToken)
        {
            var (command, arguments) = ecosystem.ToLowerInvariant() switch
            {
                "nuget" => ("dotnet", new[] { "restore" }),
                _ => (string.Empty, []),
            };

            if (string.IsNullOrEmpty(command))
            {
                return;
            }

            try
            {
                var result = await Cli.Wrap(command)
                    .WithArguments(arguments)
                    .WithWorkingDirectory(workingDirectory)
                    .WithValidation(CommandResultValidation.None)
                    .ExecuteBufferedAsync(cancellationToken);

                if (result.ExitCode != 0)
                {
                    _logger.LogWarning("{Command} restore exited {Code} in {Dir}; scanning anyway. {Error}",
                        command, result.ExitCode, workingDirectory, result.StandardError.Trim());
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Dependency restore ({Command}) failed in {Dir}; scanning anyway.", command, workingDirectory);
            }
        }

        private IReadOnlyDictionary<string, string?> BuildEnvironment()
        {
            var env = new Dictionary<string, string?>();

            if (!string.IsNullOrWhiteSpace(_options.Token))
            {
                env["SNYK_TOKEN"] = _options.Token;
            }

            // OAuth 2.0 client-credentials service account (hardening over a static token).
            if (!string.IsNullOrWhiteSpace(_options.OAuthClientId) &&
                !string.IsNullOrWhiteSpace(_options.OAuthClientSecret))
            {
                env["SNYK_OAUTH_CLIENT_ID"] = _options.OAuthClientId;
                env["SNYK_OAUTH_CLIENT_SECRET"] = _options.OAuthClientSecret;
            }

            return env;
        }
    }
}
