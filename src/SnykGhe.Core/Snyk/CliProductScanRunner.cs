namespace SnykGhe.Core.Snyk
{
    /// <summary>
    /// Shared execution and error classification for the CLI-backed Code and IaC scanners, whose only real
    /// differences are the subcommand, the publish flags, and the output parser.
    /// </summary>
    public sealed class CliProductScanRunner
    {
        private readonly SnykCliRunner _cli;
        private readonly ILogger<CliProductScanRunner> _logger;

        public CliProductScanRunner(SnykCliRunner cli, ILogger<CliProductScanRunner> logger)
        {
            _cli = cli;
            _logger = logger;
        }

        public async Task<ProductScanResult> RunAsync(
            SnykProduct product,
            List<string> args,
            ScanContext context,
            Func<string, ProductScanResult> parse,
            CancellationToken cancellationToken)
        {
            var outcome = await _cli.RunAsync(args, context.WorkingDirectory, cancellationToken);

            if (outcome.AuthenticationFailed)
            {
                return ProductScanResult.Fail(product, "Snyk OAuth authentication failed.");
            }

            if (outcome.TimedOut)
            {
                return ProductScanResult.Fail(product, $"Snyk {product} scan timed out.");
            }

            // Exit codes: 0 = no issues, 1 = issues found, 2 = CLI/usage error, 3 = no supported files.
            if (outcome.ExitCode == 3)
            {
                _logger.LogInformation("Snyk {Product}: no scannable files in {Dir}; skipping its check.", product, context.WorkingDirectory);
                return ProductScanResult.Skip(product);
            }

            if (outcome.ExitCode >= 2)
            {
                var detail = outcome.Detail;

                if (LooksNotEnabled(detail) || LooksNoScanTarget(detail))
                {
                    _logger.LogInformation("Snyk {Product} not applicable (not enabled / nothing to scan); skipping its check. {Detail}",
                        product, detail.Trim());
                    return ProductScanResult.Skip(product);
                }

                var message = string.IsNullOrWhiteSpace(detail)
                    ? $"Snyk {product} CLI exited with code {outcome.ExitCode}."
                    : detail.Trim();
                _logger.LogWarning("Snyk {Product} CLI error (exit {Code}): {Error}", product, outcome.ExitCode, message);
                return ProductScanResult.Fail(product, message);
            }

            return parse(outcome.StandardOutput);
        }

        /// <summary>Adds the flags that publish a product snapshot to the Snyk Web UI.</summary>
        public static void AddPublishArgs(List<string> args, ScanContext context, string projectNameFlag)
        {
            // `snyk code test --report` / `snyk iac test --report` require an explicit name; it is not derived.
            args.Add("--report");
            args.Add($"--{projectNameFlag}={context.ProjectName}");

            // Without an explicit remote-repo-url, --report attaches to the target auto-detected from the
            // clone's git remote, whose URL ends in .git — surfacing as a confusing owner/repo.git target.
            if (!string.IsNullOrWhiteSpace(context.RemoteRepoUrl))
            {
                args.Add($"--remote-repo-url={context.RemoteRepoUrl}");
            }

            if (!string.IsNullOrWhiteSpace(context.TargetReference))
            {
                args.Add($"--target-reference={context.TargetReference}");
            }
        }

        internal static bool LooksNotEnabled(string? stderr)
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

        internal static bool LooksNoScanTarget(string? output)
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
    }
}
