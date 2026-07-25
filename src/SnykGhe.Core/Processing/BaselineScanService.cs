using Microsoft.Extensions.Options;
using SnykGhe.Core.Configuration;
using SnykGhe.Core.GitHub;
using SnykGhe.Core.Snyk;

namespace SnykGhe.Core.Processing
{
    /// <summary>
    /// Scans a repository branch and persists a Snyk monitor snapshot under that branch's target reference.
    /// Triggered by a push to the default branch (typically a merged PR) or by the manual scan endpoint. This
    /// is the durable monitored baseline: it re-establishes the snapshot Snyk alerts against as new
    /// vulnerabilities are disclosed. It posts no Check Run, comment, or fix PR — there is no pull request.
    /// The <c>Snyk:ScanDefaultBranch</c> gate lives on the automatic push trigger, not here, so a manual scan
    /// runs regardless of that setting.
    /// </summary>
    public sealed class BaselineScanService
    {
        private readonly GitHubClientFactory _clientFactory;
        private readonly OrgPolicyResolver _policyResolver;
        private readonly RepositoryCloner _cloner;
        private readonly IOpenSourceScanner _openSourceScanner;
        private readonly ICodeScanner _codeScanner;
        private readonly IIacScanner _iacScanner;
        private readonly SnykMonitor _monitor;
        private readonly ScanCoalescer _coalescer;
        private readonly SnykOptions _snyk;
        private readonly ILogger _logger;

        public BaselineScanService(
            GitHubClientFactory clientFactory,
            OrgPolicyResolver policyResolver,
            RepositoryCloner cloner,
            IOpenSourceScanner openSourceScanner,
            ICodeScanner codeScanner,
            IIacScanner iacScanner,
            SnykMonitor monitor,
            ScanCoalescer coalescer,
            IOptions<SnykOptions> snykOptions,
            ILogger<BaselineScanService> logger)
        {
            _clientFactory = clientFactory;
            _policyResolver = policyResolver;
            _cloner = cloner;
            _openSourceScanner = openSourceScanner;
            _codeScanner = codeScanner;
            _iacScanner = iacScanner;
            _monitor = monitor;
            _coalescer = coalescer;
            _snyk = snykOptions.Value;
            _logger = logger;
        }

        public async Task ProcessAsync(BaselineScanRequest request, CancellationToken cancellationToken)
        {
            var policy = await _policyResolver.ResolveAsync(request.Owner, cancellationToken);
            if (policy.Suspended)
            {
                _logger.LogInformation("Installation for {Owner} is suspended; skipping baseline scan.", request.Owner);
                return;
            }

            _logger.LogInformation("Baseline scan of {Owner}/{Repo} default branch {Branch} ({Sha}); Snyk org {SnykOrg}",
                request.Owner, request.Repo, request.Branch, request.HeadSha, policy.SnykOrgId ?? "(default)");

            // Coalesce bursts of pushes to this branch into one in-flight scan (latest commit wins).
            var key = $"{request.Owner}/{request.Repo}#{request.Branch}".ToLowerInvariant();
            await _coalescer.RunAsync(key, request.HeadSha,
                token => RunScanAsync(request, policy, token), cancellationToken);
        }

        /// <summary>Clones and scans the branch, returning the commit SHA actually cloned (the branch tip).</summary>
        private async Task<string> RunScanAsync(BaselineScanRequest request, ResolvedPolicy policy, CancellationToken cancellationToken)
        {
            var credentials = await _clientFactory.CreateInstallationClientAsync(request.InstallationId, cancellationToken);

            var workDir = Path.Combine(Path.GetTempPath(), $"snyk-baseline-{request.Repo}-{Guid.NewGuid():N}");
            Directory.CreateDirectory(workDir);

            try
            {
                await _cloner.CloneAsync(request.CloneUrl, request.Branch, credentials.Token, workDir, cancellationToken);
                var scannedSha = await _cloner.ResolveHeadShaAsync(workDir, cancellationToken);

                // Keep the default branch's SAST / IaC snapshots current too, when those products are enabled.
                // publish:true so each --report attaches to the same default-branch target reference.
                var context = new ScanContext
                {
                    WorkingDirectory = workDir,
                    Policy = policy,
                    RemoteRepoUrl = request.RemoteRepoUrl,
                    TargetReference = request.Branch,
                    ProjectName = $"{request.Owner}/{request.Repo}",
                    Publish = true,
                };

                // Open Source is always on. Monitor is forced regardless of Snyk:Monitor: persisting the
                // default-branch snapshot is the entire purpose of this scan.
                var openSourceScan = await _openSourceScanner.ScanAsync(context, cancellationToken);
                if (openSourceScan.Failed)
                {
                    _logger.LogWarning("Baseline Open Source scan of {Owner}/{Repo}@{Branch} failed; not monitoring: {Message}",
                        request.Owner, request.Repo, request.Branch, openSourceScan.FailureMessage);
                }
                else
                {
                    await _monitor.MonitorAsync(context, forceMonitor: true, cancellationToken);
                }

                if (_snyk.ScanCode)
                {
                    await _codeScanner.ScanAsync(context, cancellationToken);
                }

                if (_snyk.ScanIac)
                {
                    await _iacScanner.ScanAsync(context, cancellationToken);
                }

                _logger.LogInformation("Baseline scan of {Owner}/{Repo} default branch {Branch} ({Sha}) complete.",
                    request.Owner, request.Repo, request.Branch, scannedSha);

                return scannedSha;
            }
            finally
            {
                TryDeleteDirectory(workDir);
            }
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
