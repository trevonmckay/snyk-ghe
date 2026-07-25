using CliWrap;
using CliWrap.Buffered;
using Microsoft.Extensions.Options;
using SnykGhe.Core.Configuration;

namespace SnykGhe.Core.Snyk
{
    /// <summary>Outcome of one Snyk CLI invocation.</summary>
    public sealed class SnykCliOutcome
    {
        public int ExitCode { get; init; }

        public string StandardOutput { get; init; } = string.Empty;

        public string StandardError { get; init; } = string.Empty;

        public bool TimedOut { get; init; }

        /// <summary>True when an OAuth token was required but could not be obtained; the CLI never ran.</summary>
        public bool AuthenticationFailed { get; init; }

        /// <summary>Snyk emits errors on stderr for some products and as JSON on stdout for others.</summary>
        public string Detail => string.IsNullOrWhiteSpace(StandardError) ? StandardOutput : StandardError;
    }

    /// <summary>
    /// Runs the Snyk CLI. Owns authentication, the per-scan timeout, and dependency restore, so the
    /// individual product scanners only build argument lists and parse output.
    /// </summary>
    public sealed class SnykCliRunner
    {
        private const string NuGetEcosystem = "nuget";

        private readonly SnykOptions _options;
        private readonly SnykOAuthTokenProvider _oauthTokenProvider;
        private readonly ILogger<SnykCliRunner> _logger;

        public SnykCliRunner(
            IOptions<SnykOptions> options,
            SnykOAuthTokenProvider oauthTokenProvider,
            ILogger<SnykCliRunner> logger)
        {
            _options = options.Value;
            _oauthTokenProvider = oauthTokenProvider;
            _logger = logger;
        }

        /// <summary>
        /// Executes the CLI, applying the configured scan timeout. Snyk exits 1 when it finds issues, which
        /// is a successful scan, so command-result validation is disabled and callers interpret the code.
        /// </summary>
        public async Task<SnykCliOutcome> RunAsync(
            IReadOnlyList<string> args,
            string workingDirectory,
            CancellationToken cancellationToken,
            bool applyTimeout = true)
        {
            var (authOk, oauthToken) = await ResolveOAuthTokenAsync(cancellationToken);
            if (!authOk)
            {
                return new SnykCliOutcome { AuthenticationFailed = true };
            }

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            if (applyTimeout)
            {
                timeout.CancelAfter(TimeSpan.FromSeconds(_options.ScanTimeoutSeconds));
            }

            try
            {
                var result = await Cli.Wrap(_options.CliPath)
                    .WithArguments(args)
                    .WithWorkingDirectory(workingDirectory)
                    .WithEnvironmentVariables(BuildEnvironment(oauthToken))
                    .WithValidation(CommandResultValidation.None)
                    .ExecuteBufferedAsync(timeout.Token);

                return new SnykCliOutcome
                {
                    ExitCode = result.ExitCode,
                    StandardOutput = result.StandardOutput,
                    StandardError = result.StandardError,
                };
            }
            catch (OperationCanceledException) when (timeout.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
            {
                _logger.LogWarning("Snyk CLI timed out after {Seconds}s in {Dir}", _options.ScanTimeoutSeconds, workingDirectory);
                return new SnykCliOutcome { TimedOut = true };
            }
        }

        /// <summary>Appends <c>--org</c> when the policy maps this GitHub org to a specific Snyk org.</summary>
        public static void AddOrgArg(List<string> args, ResolvedPolicy policy)
        {
            // No --severity-threshold: report every severity and gate in our own code, so the summary breakdown
            // matches what Snyk records rather than being pre-filtered to the gate level.
            if (!string.IsNullOrWhiteSpace(policy.SnykOrgId))
            {
                args.Add($"--org={policy.SnykOrgId}");
            }
        }

        /// <summary>
        /// For .NET projects, names each monitored Snyk project after the name inside its
        /// <c>project.assets.json</c> rather than the (identical) target-file path. Without this, every project
        /// in a multi-project solution shows up as <c>.../project.assets.json</c> and is indistinguishable in
        /// the UI. No-op for non-NuGet ecosystems, where the flag does not apply.
        /// </summary>
        public static void AddNuGetNamingArgs(List<string> args, ResolvedPolicy policy)
        {
            if (IsNuGet(policy.Ecosystem))
            {
                args.Add("--assets-project-name");
            }
        }

        public static bool IsNuGet(string ecosystem) =>
            ecosystem.Equals(NuGetEcosystem, StringComparison.OrdinalIgnoreCase);

        /// <summary>
        /// Restores dependencies so Snyk can resolve the full graph. NuGet in particular requires
        /// `dotnet restore` (project.assets.json) before `snyk test`. Best-effort: a restore failure is
        /// logged and the scan proceeds, since Snyk may still report on the manifests.
        /// </summary>
        public async Task RestoreDependenciesAsync(string workingDirectory, string ecosystem, CancellationToken cancellationToken)
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

        private async Task<(bool Ok, string? Token)> ResolveOAuthTokenAsync(CancellationToken cancellationToken)
        {
            if (!_oauthTokenProvider.IsConfigured)
            {
                return (true, null);
            }

            try
            {
                return (true, await _oauthTokenProvider.GetAccessTokenAsync(cancellationToken));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Could not obtain a Snyk OAuth access token; scan cannot authenticate.");
                return (false, null);
            }
        }

        private IReadOnlyDictionary<string, string?> BuildEnvironment(string? oauthToken)
        {
            var env = new Dictionary<string, string?>();

            if (!string.IsNullOrWhiteSpace(_options.Token))
            {
                env["SNYK_TOKEN"] = _options.Token;
            }

            // OAuth 2.0 client-credentials service account (hardening over a static token). The CLI takes the
            // already-exchanged access token via SNYK_OAUTH_TOKEN — it has no env var for client id/secret.
            if (!string.IsNullOrWhiteSpace(oauthToken))
            {
                env["SNYK_OAUTH_TOKEN"] = oauthToken;
            }

            return env;
        }
    }
}
