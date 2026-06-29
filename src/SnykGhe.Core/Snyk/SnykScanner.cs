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
        private const string NuGetEcosystem = "nuget";

        private readonly SnykOptions _options;
        private readonly SnykOAuthTokenProvider _oauthTokenProvider;
        private readonly ILogger _logger;

        public SnykScanner(IOptions<SnykOptions> options, SnykOAuthTokenProvider oauthTokenProvider, ILogger<SnykScanner> logger)
        {
            _options = options.Value;
            _oauthTokenProvider = oauthTokenProvider;
            _logger = logger;
        }

        public async Task<SnykScanResult> ScanAsync(
            string workingDirectory,
            ResolvedPolicy policy,
            CancellationToken cancellationToken)
        {
            await RestoreDependenciesAsync(workingDirectory, policy.Ecosystem, cancellationToken);

            string? oauthToken = null;
            if (_oauthTokenProvider.IsConfigured)
            {
                try
                {
                    oauthToken = await _oauthTokenProvider.GetAccessTokenAsync(cancellationToken);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Could not obtain a Snyk OAuth access token; scan cannot authenticate.");
                    return new SnykScanResult { Projects = [], Failed = true, FailureMessage = "Snyk OAuth authentication failed." };
                }
            }

            // Report every severity; the gate threshold is applied in our own code (CountAtOrAbove) so the
            // summary shows the full breakdown. Passing --severity-threshold would drop lower-severity issues
            // from the JSON, under-reporting counts relative to the monitor snapshot the check links to.
            var args = new List<string> { "test", "--json", "--all-projects" };
            AddNuGetNamingArgs(args, policy);

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
                    .WithEnvironmentVariables(BuildEnvironment(oauthToken))
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
        /// Persists the scan to the Snyk Web UI with <c>snyk monitor</c> and returns the snapshot URL the
        /// Check Run links to, or null when monitoring is disabled or the CLI produced no usable URL. A
        /// monitor failure is non-fatal: the gating test result already drives the check, so this only costs
        /// the deep link. Must run after <see cref="ScanAsync"/> in the same directory — it relies on the
        /// dependency restore that scan performed and does not repeat it.
        /// </summary>
        public async Task<string?> MonitorAsync(
            string workingDirectory,
            ResolvedPolicy policy,
            string remoteRepoUrl,
            string targetReference,
            CancellationToken cancellationToken)
        {
            if (!_options.Monitor)
            {
                return null;
            }

            string? oauthToken = null;
            if (_oauthTokenProvider.IsConfigured)
            {
                try
                {
                    oauthToken = await _oauthTokenProvider.GetAccessTokenAsync(cancellationToken);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Could not obtain a Snyk OAuth token for monitor; check will have no Snyk link.");
                    return null;
                }
            }

            var args = new List<string> { "monitor", "--json", "--all-projects" };
            AddNuGetNamingArgs(args, policy);

            if (!string.IsNullOrWhiteSpace(policy.SnykOrgId))
            {
                args.Add($"--org={policy.SnykOrgId}");
            }

            if (!string.IsNullOrWhiteSpace(remoteRepoUrl))
            {
                args.Add($"--remote-repo-url={remoteRepoUrl}");
            }

            if (!string.IsNullOrWhiteSpace(targetReference))
            {
                args.Add($"--target-reference={targetReference}");
            }

            BufferedCommandResult result;
            try
            {
                result = await Cli.Wrap(_options.CliPath)
                    .WithArguments(args)
                    .WithWorkingDirectory(workingDirectory)
                    .WithEnvironmentVariables(BuildEnvironment(oauthToken))
                    .WithValidation(CommandResultValidation.None)
                    .ExecuteBufferedAsync(cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Snyk monitor failed in {Dir}; check will have no Snyk link.", workingDirectory);
                return null;
            }

            // A non-zero exit still prints uris for the manifests that did monitor, so parse regardless.
            if (result.ExitCode != 0)
            {
                _logger.LogWarning("Snyk monitor exited {Code} in {Dir}: {Error}",
                    result.ExitCode, workingDirectory, result.StandardError.Trim());
            }

            return SnykMonitorResult.FirstUri(result.StandardOutput);
        }

        /// <summary>
        /// Runs <c>snyk code test</c> (SAST) and returns a normalized result for the Code Check Run.
        /// Reports the snapshot to the Snyk Web UI with <c>--report</c> when <paramref name="publish"/> is set.
        /// A repo with no scannable source, or an org without the Snyk Code entitlement, yields a
        /// not-applicable result so no Check Run is posted (rather than a failure).
        /// </summary>
        public async Task<ProductScanResult> ScanCodeAsync(
            string workingDirectory,
            ResolvedPolicy policy,
            bool publish,
            string projectName,
            string remoteRepoUrl,
            string targetReference,
            CancellationToken cancellationToken)
        {
            var (ok, oauthToken) = await ResolveOAuthTokenAsync(cancellationToken);
            if (!ok)
            {
                return ProductScanResult.Fail(SnykProduct.Code, "Snyk OAuth authentication failed.");
            }

            var args = new List<string> { "code", "test", "--json" };
            AddCommonArgs(args, policy);
            if (publish)
            {
                // `snyk code test --report` requires an explicit project name (it is not auto-derived).
                args.Add("--report");
                args.Add($"--project-name={projectName}");
                // Without an explicit remote-repo-url, --report attaches to the target auto-detected from the
                // clone's git remote, whose URL ends in .git — surfacing as a confusing owner/repo.git target.
                if (!string.IsNullOrWhiteSpace(remoteRepoUrl))
                {
                    args.Add($"--remote-repo-url={remoteRepoUrl}");
                }
                if (!string.IsNullOrWhiteSpace(targetReference))
                {
                    args.Add($"--target-reference={targetReference}");
                }
            }

            return await RunProductScanAsync(SnykProduct.Code, args, workingDirectory, oauthToken, SnykCodeResult.Parse, cancellationToken);
        }

        /// <summary>
        /// Runs <c>snyk iac test</c> and returns a normalized result for the IaC Check Run. Reports to the
        /// Snyk Web UI with <c>--report</c> when <paramref name="publish"/> is set. A repo with no IaC files
        /// yields a not-applicable result so no Check Run is posted.
        /// </summary>
        public async Task<ProductScanResult> ScanIacAsync(
            string workingDirectory,
            ResolvedPolicy policy,
            bool publish,
            string projectName,
            string remoteRepoUrl,
            string targetReference,
            CancellationToken cancellationToken)
        {
            var (ok, oauthToken) = await ResolveOAuthTokenAsync(cancellationToken);
            if (!ok)
            {
                return ProductScanResult.Fail(SnykProduct.Iac, "Snyk OAuth authentication failed.");
            }

            var args = new List<string> { "iac", "test", "--json" };
            AddCommonArgs(args, policy);
            if (publish)
            {
                // `snyk iac test --report` needs a target name to attach the snapshot to.
                args.Add("--report");
                args.Add($"--target-name={projectName}");
                // Group under the same target as the other products rather than a git-detected owner/repo.git.
                if (!string.IsNullOrWhiteSpace(remoteRepoUrl))
                {
                    args.Add($"--remote-repo-url={remoteRepoUrl}");
                }
                if (!string.IsNullOrWhiteSpace(targetReference))
                {
                    args.Add($"--target-reference={targetReference}");
                }
            }

            return await RunProductScanAsync(SnykProduct.Iac, args, workingDirectory, oauthToken, SnykIacResult.Parse, cancellationToken);
        }

        private static bool IsNuGet(string ecosystem) =>
            ecosystem.Equals(NuGetEcosystem, StringComparison.OrdinalIgnoreCase);

        /// <summary>
        /// For .NET projects, names each monitored Snyk project after the name inside its
        /// <c>project.assets.json</c> rather than the (identical) target-file path. Without this, every project
        /// in a multi-project solution shows up as <c>.../project.assets.json</c> and is indistinguishable in
        /// the UI. No-op for non-NuGet ecosystems, where the flag does not apply.
        /// </summary>
        private static void AddNuGetNamingArgs(List<string> args, ResolvedPolicy policy)
        {
            if (IsNuGet(policy.Ecosystem))
            {
                args.Add("--assets-project-name");
            }
        }

        private static void AddCommonArgs(List<string> args, ResolvedPolicy policy)
        {
            // No --severity-threshold: report every severity and gate in our own code, so the summary breakdown
            // matches what Snyk records rather than being pre-filtered to the gate level.
            if (!string.IsNullOrWhiteSpace(policy.SnykOrgId))
            {
                args.Add($"--org={policy.SnykOrgId}");
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

        private async Task<ProductScanResult> RunProductScanAsync(
            SnykProduct product,
            List<string> args,
            string workingDirectory,
            string? oauthToken,
            Func<string, ProductScanResult> parse,
            CancellationToken cancellationToken)
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(_options.ScanTimeoutSeconds));

            BufferedCommandResult result;
            try
            {
                result = await Cli.Wrap(_options.CliPath)
                    .WithArguments(args)
                    .WithWorkingDirectory(workingDirectory)
                    .WithEnvironmentVariables(BuildEnvironment(oauthToken))
                    .WithValidation(CommandResultValidation.None)
                    .ExecuteBufferedAsync(timeout.Token);
            }
            catch (OperationCanceledException) when (timeout.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
            {
                _logger.LogWarning("Snyk {Product} scan timed out after {Seconds}s in {Dir}", product, _options.ScanTimeoutSeconds, workingDirectory);
                return ProductScanResult.Fail(product, $"Snyk {product} scan timed out.");
            }

            // Exit codes: 0 = no issues, 1 = issues found, 2 = CLI/usage error, 3 = no supported files.
            if (result.ExitCode == 3)
            {
                _logger.LogInformation("Snyk {Product}: no scannable files in {Dir}; skipping its check.", product, workingDirectory);
                return ProductScanResult.Skip(product);
            }

            if (result.ExitCode >= 2)
            {
                // Snyk emits errors on stderr for some products and as JSON on stdout for others.
                var detail = string.IsNullOrWhiteSpace(result.StandardError) ? result.StandardOutput : result.StandardError;

                if (LooksNotEnabled(detail) || LooksNoScanTarget(detail))
                {
                    _logger.LogInformation("Snyk {Product} not applicable (not enabled / nothing to scan); skipping its check. {Detail}",
                        product, detail.Trim());
                    return ProductScanResult.Skip(product);
                }

                var message = string.IsNullOrWhiteSpace(detail)
                    ? $"Snyk {product} CLI exited with code {result.ExitCode}."
                    : detail.Trim();
                _logger.LogWarning("Snyk {Product} CLI error (exit {Code}): {Error}", product, result.ExitCode, message);
                return ProductScanResult.Fail(product, message);
            }

            return parse(result.StandardOutput);
        }

        private static bool LooksNotEnabled(string? stderr)
        {
            if (string.IsNullOrWhiteSpace(stderr))
            {
                return false;
            }

            var text = stderr.ToLowerInvariant();
            return text.Contains("not enabled")
                || text.Contains("not authorized")
                || text.Contains("is not supported")
                || text.Contains("not entitled")
                || text.Contains("snyk code is not");
        }

        private static bool LooksNoScanTarget(string? output)
        {
            if (string.IsNullOrWhiteSpace(output))
            {
                return false;
            }

            var text = output.ToLowerInvariant();
            return text.Contains("could not find any")
                || text.Contains("no iac files")
                || text.Contains("no supported files")
                || text.Contains("not found any supported")
                // Snyk IaC treats every .json/.yaml as candidate IaC and aborts on incidental non-IaC files
                // (tsconfig, package.json, …). In a repo with no real IaC that is "nothing to scan", not a failure.
                || text.Contains("failed to parse");
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
