using System.Text;
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
        private readonly IOpenSourceScanner _openSourceScanner;
        private readonly ICodeScanner _codeScanner;
        private readonly IIacScanner _iacScanner;
        private readonly SnykMonitor _monitor;
        private readonly SnykProjectUrlResolver _projectUrlResolver;
        private readonly OrgPolicyResolver _policyResolver;
        private readonly FixPullRequestService _prFixService;
        private readonly RepositoryCloner _cloner;
        private readonly GitHubOptions _gitHub;
        private readonly SnykOptions _snyk;
        private readonly ILogger _logger;

        public PullRequestCheckService(
            GitHubClientFactory clientFactory,
            IOpenSourceScanner openSourceScanner,
            ICodeScanner codeScanner,
            IIacScanner iacScanner,
            SnykMonitor monitor,
            SnykProjectUrlResolver projectUrlResolver,
            OrgPolicyResolver policyResolver,
            FixPullRequestService fixService,
            RepositoryCloner cloner,
            IOptions<GitHubOptions> gitHubOptions,
            IOptions<SnykOptions> snykOptions,
            ILogger<PullRequestCheckService> logger)
        {
            _clientFactory = clientFactory;
            _openSourceScanner = openSourceScanner;
            _codeScanner = codeScanner;
            _iacScanner = iacScanner;
            _monitor = monitor;
            _projectUrlResolver = projectUrlResolver;
            _policyResolver = policyResolver;
            _prFixService = fixService;
            _cloner = cloner;
            _gitHub = gitHubOptions.Value;
            _snyk = snykOptions.Value;
            _logger = logger;
        }

        public async Task ProcessAsync(ScanRequest request, CancellationToken cancellationToken)
        {
            var policy = await _policyResolver.ResolveAsync(request.Owner, request.Repo, cancellationToken);

            if (policy.Suspended)
            {
                _logger.LogInformation("Installation for {Owner} is suspended; skipping scan.", request.Owner);
                return;
            }

            _logger.LogInformation("Scanning {Owner}/{Repo} PR #{Pr} ({Sha}); Snyk org {SnykOrg}, gate {Gate}",
                request.Owner, request.Repo, request.PrNumber, request.HeadSha, policy.SnykOrgId ?? "(default)", policy.SeverityThreshold);

            var startedAt = DateTimeOffset.UtcNow;
            var credentials = await _clientFactory.CreateInstallationClientAsync(request.InstallationId, cancellationToken);

            // Products that will run this scan. Each gets a Check Run posted as in_progress up front (below) so
            // the PR shows live progress while the worker scans, then is moved to completed once its result is in.
            var products = new List<SnykProduct> { SnykProduct.OpenSource };
            if (_snyk.ScanCode)
            {
                products.Add(SnykProduct.Code);
            }
            if (_snyk.ScanIac)
            {
                products.Add(SnykProduct.Iac);
            }

            var checkRunIds = new Dictionary<SnykProduct, long>();
            var finalized = new HashSet<SnykProduct>();

            var workDir = Path.Combine(Path.GetTempPath(), $"snyk-{request.Repo}-{request.PrNumber}-{Guid.NewGuid():N}");
            Directory.CreateDirectory(workDir);

            try
            {
                await StartChecksAsync(credentials.Client, request, products, startedAt, checkRunIds);

                await _cloner.CloneAsync(request.CloneUrl, request.HeadRef, credentials.Token, workDir, cancellationToken);

                var projectName = $"{request.Owner}/{request.Repo}";
                var context = new ScanContext
                {
                    WorkingDirectory = workDir,
                    Policy = policy,
                    RemoteRepoUrl = request.RemoteRepoUrl,
                    TargetReference = request.HeadRef,
                    ProjectName = projectName,
                    Publish = _snyk.Monitor,
                };

                // Open Source (always on). Its raw result also drives fix PRs, so keep it alongside the
                // normalized form used for the Check Run.
                var openSourceScan = await _openSourceScanner.ScanAsync(context, cancellationToken);
                string? openSourceUrl = null;
                if (!openSourceScan.Failed)
                {
                    openSourceUrl = await _monitor.MonitorAsync(context, forceMonitor: false, cancellationToken);
                }

                var results = new List<ProductScanResult> { ToProductResult(openSourceScan, openSourceUrl) };

                if (_snyk.ScanCode)
                {
                    var codeResult = await _codeScanner.ScanAsync(context, cancellationToken);

                    // `snyk code test --report` publishes the snapshot but, unlike `snyk monitor`, does not
                    // return its URL in --json output; look it up so the Code row can deep-link.
                    if (_snyk.Monitor && !codeResult.Failed && !codeResult.NotApplicable)
                    {
                        var url = await _projectUrlResolver.ResolveAsync(SnykProduct.Code, projectName, request.HeadRef, policy, cancellationToken);
                        if (url is not null)
                        {
                            codeResult = codeResult.WithDetailsUrl(url);
                        }
                    }

                    results.Add(codeResult);
                }

                if (_snyk.ScanIac)
                {
                    results.Add(await _iacScanner.ScanAsync(context, cancellationToken));
                }

                // One Check Run per enabled product. A not-applicable product (nothing to scan / not enabled)
                // still posts a "skipped" conclusion: GitHub treats a posted skipped status as passing for a
                // required check, whereas posting nothing leaves a required check stuck on "Expected — waiting".
                foreach (var result in results)
                {
                    var (conclusion, title, summary) = result.NotApplicable
                        ? (CheckConclusion.Skipped,
                           $"No {ProductLabel(result.Product)} scan applicable",
                           $"The Snyk {ProductLabel(result.Product)} scan was skipped — nothing to scan or the product is not enabled for this org.")
                        : BuildProductReport(result, policy);

                    await CompleteCheckAsync(credentials.Client, request, checkRunIds[result.Product],
                        conclusion, title, summary, result.DetailsUrl, startedAt);
                    finalized.Add(result.Product);

                    _logger.LogInformation("Reported {Conclusion} for Snyk {Product} on {Owner}/{Repo} PR #{Pr}",
                        conclusion, result.Product, request.Owner, request.Repo, request.PrNumber);
                }

                var comment = BuildCombinedComment(results, policy);
                if (comment is not null)
                {
                    await UpsertSummaryCommentAsync(credentials.Client, request, comment, cancellationToken);
                }

                // A fix-PR failure must not fail the checks that already reported. Fix PRs come from the
                // Open Source scan only (dependency upgrades).
                try
                {
                    await _prFixService.TryOpenAsync(request, policy, openSourceScan, credentials.Client, workDir, cancellationToken);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to open fix PR for {Owner}/{Repo} PR #{Pr}", request.Owner, request.Repo, request.PrNumber);
                }
            }
            finally
            {
                // Resolve any check still in_progress — clone or a scan threw before it was completed. Without
                // this a spinning check would remain on the PR and, if it is a required check, block the merge.
                foreach (var (product, checkRunId) in checkRunIds)
                {
                    if (finalized.Contains(product))
                    {
                        continue;
                    }

                    try
                    {
                        await CompleteCheckAsync(credentials.Client, request, checkRunId, CheckConclusion.Neutral,
                            $"Snyk {ProductLabel(product)} scan could not complete",
                            "⚠️ The scan did not finish due to an unexpected error.", null, startedAt);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Could not resolve in-progress {Product} check for {Owner}/{Repo} PR #{Pr}",
                            product, request.Owner, request.Repo, request.PrNumber);
                    }
                }

                TryDeleteDirectory(workDir);
            }
        }

        /// <summary>
        /// Posts an in_progress Check Run for each product about to be scanned and records its id in
        /// <paramref name="checkRunIds"/> so <see cref="CompleteCheckAsync"/> can later move it to completed.
        /// The dictionary is filled as each check is created, so a mid-loop failure still leaves the
        /// already-created checks tracked for the caller's finally block to resolve.
        /// </summary>
        private async Task StartChecksAsync(
            GitHubClient client,
            ScanRequest request,
            IReadOnlyList<SnykProduct> products,
            DateTimeOffset startedAt,
            Dictionary<SnykProduct, long> checkRunIds)
        {
            foreach (var product in products)
            {
                var label = ProductLabel(product);
                var created = await client.Check.Run.Create(request.Owner, request.Repo,
                    new NewCheckRun(ProductCheckName(product), request.HeadSha)
                    {
                        Status = CheckStatus.InProgress,
                        StartedAt = startedAt,
                        Output = new NewCheckRunOutput($"Snyk {label} scan in progress", $"Running the Snyk {label} scan…"),
                    });
                checkRunIds[product] = created.Id;
            }
        }

        /// <summary>Moves a previously posted in_progress Check Run to its terminal completed state.</summary>
        private async Task CompleteCheckAsync(
            GitHubClient client,
            ScanRequest request,
            long checkRunId,
            CheckConclusion conclusion,
            string title,
            string summary,
            string? detailsUrl,
            DateTimeOffset startedAt)
        {
            await client.Check.Run.Update(request.Owner, request.Repo, checkRunId, new CheckRunUpdate
            {
                Status = CheckStatus.Completed,
                Conclusion = conclusion,
                StartedAt = startedAt,
                CompletedAt = DateTimeOffset.UtcNow,
                DetailsUrl = detailsUrl,
                Output = new NewCheckRunOutput(title, summary),
            });
        }

        private static ProductScanResult ToProductResult(SnykScanResult scan, string? detailsUrl)
        {
            if (scan.Failed)
            {
                return new ProductScanResult
                {
                    Product = SnykProduct.OpenSource,
                    Findings = [],
                    Failed = true,
                    FailureMessage = scan.FailureMessage,
                    DetailsUrl = detailsUrl,
                };
            }

            var findings = scan.AllVulnerabilities
                .Select(v => new SnykFinding
                {
                    Severity = v.Severity,
                    Title = v.Title,
                    Location = $"{v.PackageName}@{v.Version}",
                    FixedIn = v.FixedIn,
                    IssueType = v.Type,
                })
                .ToList();

            return new ProductScanResult { Product = SnykProduct.OpenSource, Findings = findings, DetailsUrl = detailsUrl };
        }

        private static (CheckConclusion Conclusion, string Title, string Summary) BuildProductReport(ProductScanResult result, ResolvedPolicy policy)
        {
            var label = ProductLabel(result.Product);

            if (result.Failed)
            {
                // Tooling error: surface it without hard-blocking the PR.
                return (CheckConclusion.Neutral, $"Snyk {label} scan could not complete",
                    $"⚠️ The Snyk {label} scan did not complete: {result.FailureMessage}");
            }

            var threshold = policy.Threshold;
            var blocking = result.CountAtOrAbove(threshold);
            var total = result.Findings.Count;
            var conclusion = blocking > 0 ? CheckConclusion.Failure : CheckConclusion.Success;

            var critical = result.CountBySeverity(SnykSeverity.Critical);
            var high = result.CountBySeverity(SnykSeverity.High);
            var title = total == 0
                ? $"No {label} issues"
                : $"{total} {label} issue(s) found ({critical} critical, {high} high)";

            return (conclusion, title, BuildSummary(result, policy, conclusion));
        }

        private static string BuildSummary(ProductScanResult result, ResolvedPolicy policy, CheckConclusion conclusion)
        {
            var threshold = policy.Threshold;
            var blocking = result.CountAtOrAbove(threshold);

            var sb = new StringBuilder();
            sb.AppendLine($"## {(conclusion == CheckConclusion.Success ? "✅" : "❌")} Snyk {ProductLabel(result.Product)}");
            sb.AppendLine();
            sb.AppendLine("| Severity | Count |");
            sb.AppendLine("| --- | --- |");
            sb.AppendLine($"| Critical | {result.CountBySeverity(SnykSeverity.Critical)} |");
            sb.AppendLine($"| High | {result.CountBySeverity(SnykSeverity.High)} |");
            sb.AppendLine($"| Medium | {result.CountBySeverity(SnykSeverity.Medium)} |");
            sb.AppendLine($"| Low | {result.CountBySeverity(SnykSeverity.Low)} |");
            sb.AppendLine();
            sb.AppendLine($"Gate threshold: **{threshold}** and above ({blocking} blocking).");

            var top = result.Findings
                .OrderByDescending(f => SnykSeverityExtensions.Parse(f.Severity))
                .Take(15)
                .ToList();

            if (top.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("| Severity | Issue | Location | Fixed in |");
                sb.AppendLine("| --- | --- | --- | --- |");
                foreach (var f in top)
                {
                    var fixedIn = f.FixedIn is { Count: > 0 } ? string.Join(", ", f.FixedIn) : "—";
                    sb.AppendLine($"| {f.Severity} | {f.Title} | {f.Location ?? "—"} | {fixedIn} |");
                }
            }

            return sb.ToString();
        }

        // Hidden marker that identifies this app's summary comment so each scan edits the same one in place
        // instead of stacking a new comment per run.
        private const string CommentMarker = "<!-- snyk-ghe:summary -->";

        /// <summary>
        /// Posts the summary comment, editing the app's existing comment on the PR when one is present so a
        /// re-scan updates a single comment rather than appending a new one.
        /// </summary>
        private static async Task UpsertSummaryCommentAsync(GitHubClient client, ScanRequest request, string body, CancellationToken cancellationToken)
        {
            var marked = $"{CommentMarker}\n{body}";

            var existing = await client.Issue.Comment.GetAllForIssue(request.Owner, request.Repo, request.PrNumber);
            var mine = existing.FirstOrDefault(c => c.Body is not null && c.Body.Contains(CommentMarker, StringComparison.Ordinal));

            if (mine is not null)
            {
                await client.Issue.Comment.Update(request.Owner, request.Repo, mine.Id, marked);
            }
            else
            {
                await client.Issue.Comment.Create(request.Owner, request.Repo, request.PrNumber, marked);
            }
        }

        /// <summary>
        /// Builds a single summary comment with one row per scan engine — Open Source Security, Licenses,
        /// Code Security, Infrastructure as Code — mirroring Snyk's native PR comment.
        /// </summary>
        private static string? BuildCombinedComment(IReadOnlyList<ProductScanResult> results, ResolvedPolicy policy)
        {
            if (results.Count == 0)
            {
                return null;
            }

            var rows = new List<string>();
            foreach (var result in results)
            {
                if (result.Product == SnykProduct.OpenSource)
                {
                    rows.Add(EngineRow("Open Source Security", result, policy, f => !IsLicense(f)));
                    rows.Add(EngineRow("Licenses", result, policy, IsLicense));
                }
                else
                {
                    rows.Add(EngineRow(EngineLabel(result.Product), result, policy, _ => true));
                }
            }

            var applicable = results.Where(r => !r.NotApplicable && !r.Failed).ToList();
            var grandTotal = applicable.Sum(r => r.Findings.Count);
            var anyBlocking = applicable.Any(r => r.CountAtOrAbove(policy.Threshold) > 0);

            string header;
            if (anyBlocking)
            {
                header = $"### ❌ Snyk found issues at or above the **{policy.SeverityThreshold}** gate.";
            }
            else if (grandTotal > 0)
            {
                header = $"### ✅ Snyk checks have passed. Issues were found below the **{policy.SeverityThreshold}** gate.";
            }
            else
            {
                header = "### ✅ Snyk checks have passed. No issues have been found so far.";
            }

            if (results.Any(r => r.Failed))
            {
                header += "\n\n> ⚠️ One or more scans could not complete — see the individual checks for details.";
            }

            var sb = new StringBuilder();
            sb.AppendLine(header);
            sb.AppendLine();
            sb.AppendLine($"| Status | Scan Engine | 🔴 Critical | 🟠 High | 🟡 Medium | ⚪ Low | Total ({grandTotal}) |");
            sb.AppendLine("| :---: | --- | :---: | :---: | :---: | :---: | :---: |");
            foreach (var row in rows)
            {
                sb.AppendLine(row);
            }

            return sb.ToString();
        }

        private static string EngineRow(string label, ProductScanResult result, ResolvedPolicy policy, Func<SnykFinding, bool> include)
        {
            if (result.NotApplicable)
            {
                return $"| ⏭️ | {label} | — | — | — | — | skipped |";
            }

            if (result.Failed)
            {
                return $"| ⚠️ | {label} | — | — | — | — | could not complete |";
            }

            var findings = result.Findings.Where(include).ToList();
            int Count(SnykSeverity s) => findings.Count(f => SnykSeverityExtensions.Parse(f.Severity) == s);

            var blocking = findings.Count(f => SnykSeverityExtensions.Parse(f.Severity) >= policy.Threshold);
            var icon = blocking > 0 ? "❌" : "✅";
            var total = findings.Count;
            var totalCell = result.DetailsUrl is { Length: > 0 } url ? $"[{total} issues]({url})" : $"{total} issues";

            return $"| {icon} | {label} | {Count(SnykSeverity.Critical)} | {Count(SnykSeverity.High)} | {Count(SnykSeverity.Medium)} | {Count(SnykSeverity.Low)} | {totalCell} |";
        }

        private static bool IsLicense(SnykFinding finding) =>
            string.Equals(finding.IssueType, "license", StringComparison.OrdinalIgnoreCase);

        private static string EngineLabel(SnykProduct product) => product switch
        {
            SnykProduct.Code => "Code Security",
            SnykProduct.Iac => "Infrastructure as Code",
            _ => ProductLabel(product),
        };

        // Check run names follow a "<scan-type>/<base>" convention (e.g. sca/snyk, sast/snyk, iac/snyk) so
        // the three product checks sort together and read as a family in the PR's Checks list.
        private string ProductCheckName(SnykProduct product) => $"{ProductCode(product)}/{_gitHub.CheckRunName}";

        private static string ProductCode(SnykProduct product) => product switch
        {
            SnykProduct.OpenSource => "sca",
            SnykProduct.Code => "sast",
            SnykProduct.Iac => "iac",
            _ => "snyk",
        };

        private static string ProductLabel(SnykProduct product) => product switch
        {
            SnykProduct.OpenSource => "Open Source",
            SnykProduct.Code => "Code",
            SnykProduct.Iac => "IaC",
            _ => product.ToString(),
        };

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
