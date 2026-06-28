using System.Text;
using CliWrap;
using CliWrap.Buffered;
using Microsoft.Extensions.Options;
using Octokit;
using SnykGhe.Core.Configuration;
using SnykGhe.Core.Fix;
using SnykGhe.Core.GitHub;
using SnykGhe.Core.Snyk;

namespace SnykGhe.Core.Processing
{
    /// <summary>
    /// Phase 1 pipeline: check out a pull request head, run Snyk under the org's resolved policy, and
    /// publish a Check Run plus a summary comment under the App's bot identity.
    /// </summary>
    public sealed class PullRequestCheckService
    {
        private readonly GitHubClientFactory _clientFactory;
        private readonly SnykScanner _scanner;
        private readonly OrgPolicyResolver _policyResolver;
        private readonly FixPullRequestService _prFixService;
        private readonly GitHubOptions _gitHub;
        private readonly ILogger _logger;

        public PullRequestCheckService(
            GitHubClientFactory clientFactory,
            SnykScanner scanner,
            OrgPolicyResolver policyResolver,
            FixPullRequestService fixService,
            IOptions<GitHubOptions> gitHubOptions,
            ILogger<PullRequestCheckService> logger)
        {
            _clientFactory = clientFactory;
            _scanner = scanner;
            _policyResolver = policyResolver;
            _prFixService = fixService;
            _gitHub = gitHubOptions.Value;
            _logger = logger;
        }

        public async Task ProcessAsync(ScanRequest request, CancellationToken cancellationToken)
        {
            var policy = await _policyResolver.ResolveAsync(request.Owner, cancellationToken);

            if (policy.Suspended)
            {
                _logger.LogInformation("Installation for {Owner} is suspended; skipping scan.", request.Owner);
                return;
            }

            _logger.LogInformation("Scanning {Owner}/{Repo} PR #{Pr} ({Sha}); Snyk org {SnykOrg}, gate {Gate}",
                request.Owner, request.Repo, request.PrNumber, request.HeadSha, policy.SnykOrgId ?? "(default)", policy.SeverityThreshold);

            var startedAt = DateTimeOffset.UtcNow;
            var credentials = await _clientFactory.CreateInstallationClientAsync(request.InstallationId);

            var workDir = Path.Combine(Path.GetTempPath(), $"snyk-{request.Repo}-{request.PrNumber}-{Guid.NewGuid():N}");
            Directory.CreateDirectory(workDir);

            try
            {
                await CloneAsync(request, credentials.Token, workDir, cancellationToken);

                var scanResult = await _scanner.ScanAsync(workDir, policy, cancellationToken);
                var (conclusion, title, summary) = BuildReport(scanResult, policy);

                await credentials.Client.Check.Run.Create(request.Owner, request.Repo, new NewCheckRun(_gitHub.CheckRunName, request.HeadSha)
                {
                    Status = CheckStatus.Completed,
                    Conclusion = conclusion,
                    StartedAt = startedAt,
                    CompletedAt = DateTimeOffset.UtcNow,
                    Output = new NewCheckRunOutput(title, summary),
                });

                await credentials.Client.Issue.Comment.Create(request.Owner, request.Repo, request.PrNumber, summary);

                _logger.LogInformation("Reported {Conclusion} for {Owner}/{Repo} PR #{Pr}",
                    conclusion, request.Owner, request.Repo, request.PrNumber);

                // A fix-PR failure must not fail the check that already reported successfully.
                try
                {
                    await _prFixService.TryOpenAsync(request, policy, scanResult, credentials.Client, workDir, cancellationToken);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to open fix PR for {Owner}/{Repo} PR #{Pr}", request.Owner, request.Repo, request.PrNumber);
                }
            }
            finally
            {
                TryDeleteDirectory(workDir);
            }
        }

        private async Task CloneAsync(ScanRequest request, string token, string workDir, CancellationToken cancellationToken)
        {
            // GitHub App installation tokens authenticate git over HTTPS as x-access-token.
            var authUrl = request.CloneUrl.Replace("https://", $"https://x-access-token:{token}@", StringComparison.Ordinal);

            var result = await Cli.Wrap("git")
                .WithArguments(["clone", "--depth", "1", "--branch", request.HeadRef, authUrl, workDir])
                .WithValidation(CommandResultValidation.None)
                .ExecuteBufferedAsync(cancellationToken);

            if (result.ExitCode != 0)
            {
                throw new InvalidOperationException($"git clone failed (exit {result.ExitCode}): {result.StandardError.Trim()}");
            }
        }

        private static (CheckConclusion Conclusion, string Title, string Summary) BuildReport(SnykScanResult scan, ResolvedPolicy policy)
        {
            if (scan.Failed)
            {
                // Tooling error: surface it without hard-blocking the PR.
                return (CheckConclusion.Neutral, "Snyk scan could not complete",
                    $"⚠️ The Snyk scan did not complete: {scan.FailureMessage}");
            }

            var threshold = policy.Threshold;
            var blocking = scan.CountAtOrAbove(threshold);
            var critical = scan.AllVulnerabilities.Count(v => SnykSeverityExtensions.Parse(v.Severity) == SnykSeverity.Critical);
            var high = scan.AllVulnerabilities.Count(v => SnykSeverityExtensions.Parse(v.Severity) == SnykSeverity.High);
            var medium = scan.AllVulnerabilities.Count(v => SnykSeverityExtensions.Parse(v.Severity) == SnykSeverity.Medium);
            var low = scan.AllVulnerabilities.Count(v => SnykSeverityExtensions.Parse(v.Severity) == SnykSeverity.Low);
            var total = scan.AllVulnerabilities.Count();

            var conclusion = blocking > 0 ? CheckConclusion.Failure : CheckConclusion.Success;
            var title = total == 0
                ? "No known vulnerabilities"
                : $"{total} issue(s) found ({critical} critical, {high} high)";

            var sb = new StringBuilder();
            sb.AppendLine($"## {(conclusion == CheckConclusion.Success ? "✅" : "❌")} Snyk security scan");
            sb.AppendLine();
            sb.AppendLine("| Severity | Count |");
            sb.AppendLine("| --- | --- |");
            sb.AppendLine($"| Critical | {critical} |");
            sb.AppendLine($"| High | {high} |");
            sb.AppendLine($"| Medium | {medium} |");
            sb.AppendLine($"| Low | {low} |");
            sb.AppendLine();
            sb.AppendLine($"Gate threshold: **{threshold}** and above ({blocking} blocking).");

            var top = scan.AllVulnerabilities
                .OrderByDescending(v => SnykSeverityExtensions.Parse(v.Severity))
                .Take(15)
                .ToList();

            if (top.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("| Package | Version | Severity | Issue | Fixed in |");
                sb.AppendLine("| --- | --- | --- | --- | --- |");
                foreach (var v in top)
                {
                    var fixedIn = v.FixedIn is { Count: > 0 } ? string.Join(", ", v.FixedIn) : "—";
                    sb.AppendLine($"| {v.PackageName} | {v.Version} | {v.Severity} | {v.Title} | {fixedIn} |");
                }
            }

            return (conclusion, title, sb.ToString());
        }

        private void TryDeleteDirectory(string path)
        {
            try
            {
                if (Directory.Exists(path))
                {
                    Directory.Delete(path, recursive: true);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to clean up working directory {Dir}", path);
            }
        }
    }
}
