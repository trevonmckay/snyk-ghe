using System.Text.Json;
using System.Text.Json.Nodes;
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
        private readonly IHostApplicationLifetime _appLifetime;
        private readonly ILogger<SnykCliRunner> _logger;

        public SnykCliRunner(
            IOptions<SnykOptions> options,
            SnykOAuthTokenProvider oauthTokenProvider,
            IHostApplicationLifetime appLifetime,
            ILogger<SnykCliRunner> logger)
        {
            _options = options.Value;
            _oauthTokenProvider = oauthTokenProvider;
            _appLifetime = appLifetime;
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
            bool applyTimeout = true,
            int? timeoutSecondsOverride = null)
        {
            var (authOk, oauthToken) = await ResolveOAuthTokenAsync(cancellationToken);
            if (!authOk)
            {
                return new SnykCliOutcome { AuthenticationFailed = true };
            }

            var timeoutSeconds = timeoutSecondsOverride ?? _options.ScanTimeoutSeconds;
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            if (applyTimeout)
            {
                timeout.CancelAfter(TimeSpan.FromSeconds(timeoutSeconds));
            }

            try
            {
                var result = await Cli.Wrap(_options.CliPath)
                    .WithArguments(args)
                    .WithWorkingDirectory(workingDirectory)
                    .WithEnvironmentVariables(BuildEnvironment(oauthToken))
                    .WithValidation(CommandResultValidation.None)
                    .ExecuteBufferedAsync(timeout.Token);

                // A signal-killed CLI (exit ≥ 128) coinciding with host shutdown means the replica is being
                // scaled in / recycled mid-scan, not that the scan failed. Surface it as a retryable
                // interruption so the delivery is redelivered and re-run on a healthy replica, rather than
                // classifying the signal code (143/137) as a real CLI error that reports "could not complete".
                if (IsShutdownInterruption(result.ExitCode, _appLifetime.ApplicationStopping.IsCancellationRequested))
                {
                    _logger.LogInformation(
                        "Snyk CLI killed by signal (exit {Code}) during host shutdown in {Dir}; delivery will be redelivered.",
                        result.ExitCode, workingDirectory);
                    throw new ScanInterruptedException(result.ExitCode);
                }

                return new SnykCliOutcome
                {
                    ExitCode = result.ExitCode,
                    StandardOutput = result.StandardOutput,
                    StandardError = result.StandardError,
                };
            }
            catch (OperationCanceledException) when (timeout.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
            {
                _logger.LogWarning("Snyk CLI timed out after {Seconds}s in {Dir}", timeoutSeconds, workingDirectory);
                return new SnykCliOutcome { TimedOut = true };
            }
        }

        /// <summary>
        /// True when a CLI outcome should be treated as a shutdown interruption rather than a scan failure:
        /// the process was killed by a signal (POSIX reports 128 + signal, so ≥ 128 — e.g. 143 SIGTERM,
        /// 137 SIGKILL) and the host is stopping. Requiring the host-stopping condition is what separates a
        /// scale-in/recycle from an unrelated kill such as an OOM of the child (which is a genuine, non-retryable
        /// scan failure and must still report rather than redeliver forever). Snyk's own exit codes are 0–3,
        /// so a code ≥ 128 is unambiguously an external signal.
        /// </summary>
        internal static bool IsShutdownInterruption(int exitCode, bool hostStopping) =>
            hostStopping && exitCode >= 128;

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

        /// <summary>
        /// Appends <c>--exclude</c> with the policy's directory/file names when any are configured. The names
        /// are already sanitized by the resolver (trimmed, de-duplicated, path-like entries dropped), so this
        /// only joins them. Applies to the <c>--all-projects</c> Open Source scan and monitor; the value is a
        /// comma-separated list of names, never paths.
        /// </summary>
        public static void AddExcludeArgs(List<string> args, ResolvedPolicy policy)
        {
            if (policy.ExcludeDirs.Count > 0)
            {
                args.Add($"--exclude={string.Join(",", policy.ExcludeDirs)}");
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

            // `dotnet restore` honours any global.json SDK pin in the cloned repo. When that pins a
            // feature band newer than the SDK baked into this worker image, restore fails with
            // "compatible SDK not found" and Snyk cannot resolve the .NET dependency graph. The band
            // is irrelevant to dependency resolution, so drop the `sdk` pin from any global.json for
            // the scan and let restore use the image's installed SDK. (Reached only for nuget: the
            // switch above returns an empty command for every other ecosystem.)
            NeutralizeSdkPins(workingDirectory);

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

        /// <summary>
        /// Strips the <c>sdk</c> pin from every <c>global.json</c> under
        /// <paramref name="workingDirectory"/> so <c>dotnet restore</c> uses this image's installed SDK
        /// instead of failing when the scanned repo pins an SDK feature band newer than the image
        /// carries. Only the <c>sdk</c> section is removed; other settings (such as <c>msbuild-sdks</c>,
        /// which restore does need to resolve MSBuild project SDKs) are preserved. Dependency
        /// resolution does not depend on the exact band, and the checkout is an ephemeral clone, so the
        /// edit is not undone. Best-effort: a file that cannot be read or rewritten is logged and left
        /// in place.
        /// </summary>
        private void NeutralizeSdkPins(string workingDirectory)
        {
            IEnumerator<string> pins;
            try
            {
                pins = Directory.EnumerateFiles(workingDirectory, "global.json", SearchOption.AllDirectories)
                    .GetEnumerator();
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Could not scan for global.json under {Dir}; restore will honour any SDK pin.", workingDirectory);
                return;
            }

            // Enumerate defensively: the AllDirectories walk is lazy and can throw partway through on an
            // unreadable subdirectory. Neutralize every pin we reach rather than abandoning the ones
            // already found.
            using (pins)
            {
                while (true)
                {
                    string pin;
                    try
                    {
                        if (!pins.MoveNext())
                        {
                            break;
                        }

                        pin = pins.Current;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Stopped scanning for global.json under {Dir}; any pins past this point remain.", workingDirectory);
                        break;
                    }

                    NeutralizeSdkPin(pin);
                }
            }
        }

        /// <summary>
        /// Removes the <c>sdk</c> section from a single <c>global.json</c>, leaving the rest of the file
        /// intact. A file with no <c>sdk</c> section, or one that cannot be parsed or rewritten, is left
        /// as-is.
        /// </summary>
        private void NeutralizeSdkPin(string pin)
        {
            try
            {
                var documentOptions = new JsonDocumentOptions
                {
                    CommentHandling = JsonCommentHandling.Skip,
                    AllowTrailingCommas = true,
                };

                if (JsonNode.Parse(File.ReadAllText(pin), documentOptions: documentOptions) is not JsonObject root
                    || !root.Remove("sdk"))
                {
                    return;
                }

                File.WriteAllText(pin, root.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
                _logger.LogInformation(
                    "Dropped the SDK pin from {Path} so dotnet restore uses the image SDK; other settings kept.", pin);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Could not drop the SDK pin from {Path}; restore may fail if it pins a newer SDK.", pin);
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
