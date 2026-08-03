using Octokit.Webhooks;
using Octokit.Webhooks.Events;
using Octokit.Webhooks.Events.CheckRun;
using Octokit.Webhooks.Events.Installation;
using Octokit.Webhooks.Events.PullRequest;
using Microsoft.Extensions.Options;
using Octokit.Webhooks.Models;
using SnykGhe.Core.Configuration;
using SnykGhe.Core.Infrastructure;
using SnykGhe.Core.Processing;
using SnykGhe.Core.Snyk;
using SnykGhe.Core.Storage;

namespace SnykGhe.Core.Webhooks
{
    /// <summary>
    /// Single dispatch point for every webhook delivery (signature already validated at the front door):
    /// pull request events run a scan; installation events maintain the registry. This runs on the queue
    /// consumer side, so the scan executes inline — durability and back-pressure are provided by the
    /// upstream webhook queue rather than a second in-process hop.
    /// </summary>
    public sealed class GitHubWebhookEventProcessor : WebhookEventProcessor
    {
        private readonly PullRequestCheckService _prCheckService;
        private readonly BaselineScanService _baselineScanService;
        private readonly IGitHubInstallationRegistry _registry;
        private readonly OrgPolicyResolver _policyResolver;
        private readonly SnykProjectCleanupService _cleanupService;
        private readonly SnykOptions _snyk;
        private readonly ILogger _logger;

        public GitHubWebhookEventProcessor(
            PullRequestCheckService prCheckService,
            BaselineScanService baselineScanService,
            IGitHubInstallationRegistry registry,
            OrgPolicyResolver policyResolver,
            SnykProjectCleanupService cleanupService,
            IOptions<SnykOptions> snykOptions,
            ILogger<GitHubWebhookEventProcessor> logger)
        {
            this._prCheckService = prCheckService;
            this._baselineScanService = baselineScanService;
            this._registry = registry;
            this._policyResolver = policyResolver;
            this._cleanupService = cleanupService;
            this._snyk = snykOptions.Value;
            this._logger = logger;
        }

        // ready_for_review is included so a draft PR gets its first scan when it is marked ready (the draft
        // guard below skips the earlier draft 'opened'/'synchronize' deliveries).
        private static readonly HashSet<string> ScanTriggeringActions =
            new(StringComparer.OrdinalIgnoreCase) { "opened", "synchronize", "reopened", "ready_for_review" };

        protected override async ValueTask ProcessPullRequestWebhookAsync(
            WebhookHeaders headers,
            PullRequestEvent pullRequestEvent,
            PullRequestAction action,
            CancellationToken cancellationToken = default)
        {
            if (pullRequestEvent.Action is not string actionName || !ScanTriggeringActions.Contains(actionName))
            {
                return;
            }

            // Draft PRs are not scanned. ready_for_review fires with Draft already cleared, so that
            // transition is what triggers the first scan of a PR opened as a draft.
            if (pullRequestEvent.PullRequest.Draft)
            {
                _logger.LogInformation("Pull request #{Pr} is a draft; skipping scan.", pullRequestEvent.Number);
                return;
            }

            if (pullRequestEvent.Installation is null ||
                pullRequestEvent.Repository is { CloneUrl: null } or null)
            {
                _logger.LogWarning("Pull request event missing installation or repository clone URL; ignoring.");
                return;
            }

            await ScanPullRequestAsync(
                pullRequestEvent.Installation.Id,
                pullRequestEvent.Repository.Owner.Login,
                pullRequestEvent.Repository.Name,
                pullRequestEvent.Repository.CloneUrl,
                (int)pullRequestEvent.Number,
                pullRequestEvent.PullRequest.Head.Ref,
                pullRequestEvent.PullRequest.Head.Sha,
                cancellationToken);
        }

        /// <summary>
        /// Re-runs a scan when a user re-triggers the Snyk check run from a PR's Checks tab. Two triggers land
        /// here, both delivered by GitHub only to the App that owns the check run (so it is always our own
        /// check): <c>rerequested</c> (the built-in "Re-run", when GitHub surfaces it) and
        /// <c>requested_action</c> (our "Re-scan" button — the reliable path, since GitHub does not offer a
        /// built-in per-check re-run for third-party App checks). Only one action button is defined, so the
        /// requested_action identifier is not inspected. A check run with no associated pull request (e.g. a
        /// branch not in a PR) is ignored — this App only scans pull requests.
        /// </summary>
        protected override async ValueTask ProcessCheckRunWebhookAsync(
            WebhookHeaders headers,
            CheckRunEvent checkRunEvent,
            CheckRunAction action,
            CancellationToken cancellationToken = default)
        {
            if (checkRunEvent.Action is not string actionName ||
                !(string.Equals(actionName, "rerequested", StringComparison.OrdinalIgnoreCase) ||
                  string.Equals(actionName, "requested_action", StringComparison.OrdinalIgnoreCase)))
            {
                return;
            }

            if (checkRunEvent.Installation is null ||
                checkRunEvent.Repository is { CloneUrl: null } or null)
            {
                _logger.LogWarning("check_run event missing installation or repository clone URL; ignoring.");
                return;
            }

            var pullRequest = checkRunEvent.CheckRun.PullRequests.FirstOrDefault();
            if (pullRequest is null)
            {
                _logger.LogInformation("check_run 'rerequested' has no associated pull request; ignoring.");
                return;
            }

            await ScanPullRequestAsync(
                checkRunEvent.Installation.Id,
                checkRunEvent.Repository.Owner.Login,
                checkRunEvent.Repository.Name,
                checkRunEvent.Repository.CloneUrl,
                (int)pullRequest.Number,
                pullRequest.Head.Ref,
                checkRunEvent.CheckRun.HeadSha,
                cancellationToken);
        }

        private async ValueTask ScanPullRequestAsync(
            long installationId,
            string owner,
            string repo,
            string cloneUrl,
            int prNumber,
            string headRef,
            string headSha,
            CancellationToken cancellationToken)
        {
            var request = new ScanRequest
            {
                InstallationId = installationId,
                Owner = owner,
                Repo = repo,
                CloneUrl = cloneUrl,
                PrNumber = prNumber,
                HeadRef = headRef,
                HeadSha = headSha,
            };

            _logger.LogInformation("Scanning {Owner}/{Repo} PR #{Pr}", request.Owner, request.Repo, request.PrNumber);
            await _prCheckService.ProcessAsync(request, cancellationToken);
        }

        /// <summary>
        /// Cleans up Snyk when a branch is deleted. Each PR scan publishes a Snyk branch reference (via
        /// <c>snyk monitor --target-reference</c>); GitHub auto-deletes the branch once the PR closes, which
        /// would otherwise leave that reference orphaned. Tag deletions carry the same event but no Snyk
        /// projects, so they are ignored. Best-effort — a cleanup failure never surfaces to GitHub.
        /// </summary>
        protected override async ValueTask ProcessDeleteWebhookAsync(
            WebhookHeaders headers,
            DeleteEvent deleteEvent,
            CancellationToken cancellationToken = default)
        {
            if (deleteEvent.RefType != RefType.Branch)
            {
                return;
            }

            if (deleteEvent.Repository is not { CloneUrl: { } cloneUrl } repository)
            {
                _logger.LogWarning("delete event missing repository clone URL; skipping Snyk cleanup.");
                return;
            }

            var gitHubOrg = repository.Owner.Login;
            // Cleanup only needs the Snyk org mapping; excludes don't apply to project teardown, so skip the
            // per-repo config lookup by resolving org-level policy alone.
            var policy = await _policyResolver.ResolveAsync(gitHubOrg, repo: null, cancellationToken);

            if (policy.Suspended)
            {
                _logger.LogInformation("Installation for {Org} is suspended; skipping Snyk cleanup.", LogSanitizer.Clean(gitHubOrg));
                return;
            }

            if (string.IsNullOrWhiteSpace(policy.SnykOrgId))
            {
                _logger.LogInformation("No Snyk org mapped for {Org}; skipping Snyk cleanup.", LogSanitizer.Clean(gitHubOrg));
                return;
            }

            var remoteRepoUrl = ScanRequest.NormalizeRemoteRepoUrl(cloneUrl);
            _logger.LogInformation("Branch {Ref} deleted on {Repo}; cleaning up Snyk projects.",
                LogSanitizer.Clean(deleteEvent.Ref), LogSanitizer.Clean(repository.FullName));

            await _cleanupService.DeleteBranchProjectsAsync(policy.SnykOrgId, remoteRepoUrl, deleteEvent.Ref, cancellationToken);
        }

        /// <summary>
        /// Runs a baseline scan when the default branch is pushed to (typically the commit a merged PR
        /// produces), re-establishing the durable <c>snyk monitor</c> snapshot Snyk alerts against as new
        /// vulnerabilities are disclosed. Only the default branch is scanned — PR branches are covered by the
        /// pull_request scan. Branch/tag creation and deletion also arrive as push events; a deletion carries
        /// the all-zero SHA and is handled by the delete webhook, so non-default-branch and deletion pushes
        /// are ignored here.
        /// </summary>
        protected override async ValueTask ProcessPushWebhookAsync(
            WebhookHeaders headers,
            PushEvent pushEvent,
            CancellationToken cancellationToken = default)
        {
            // ScanDefaultBranch gates only the automatic push trigger; the manual scan endpoint bypasses it.
            if (!_snyk.ScanDefaultBranch)
            {
                return;
            }

            if (pushEvent.Installation is null ||
                pushEvent.Repository is not { CloneUrl: { } cloneUrl, DefaultBranch: { } defaultBranch } repository)
            {
                _logger.LogWarning("push event missing installation, clone URL, or default branch; ignoring.");
                return;
            }

            if (pushEvent.Deleted ||
                !string.Equals(pushEvent.Ref, $"refs/heads/{defaultBranch}", StringComparison.Ordinal))
            {
                return;
            }

            await _baselineScanService.ProcessAsync(
                new BaselineScanRequest
                {
                    InstallationId = pushEvent.Installation.Id,
                    Owner = repository.Owner.Login,
                    Repo = repository.Name,
                    CloneUrl = cloneUrl,
                    Branch = defaultBranch,
                    HeadSha = pushEvent.After,
                },
                cancellationToken);
        }

        protected override async ValueTask ProcessInstallationWebhookAsync(
            WebhookHeaders headers,
            InstallationEvent installationEvent,
            InstallationAction action,
            CancellationToken cancellationToken = default)
        {
            var install = installationEvent.Installation;
            var org = install.Account.Login;
            var orgForLog = LogSanitizer.Clean(org);

            switch (installationEvent.Action?.ToLowerInvariant())
            {
                case "created":
                case "unsuspend":
                case "new_permissions_accepted":
                    await _registry.SeedAsync(install.Id, org, install.Account.Id, cancellationToken);
                    _logger.LogInformation("Registered installation {InstallationId} for org {Org}", install.Id, orgForLog);
                    break;

                case "suspend":
                    await _registry.SetSuspendedAsync(org, suspended: true, cancellationToken);
                    _logger.LogInformation("Suspended installation for org {Org}", orgForLog);
                    break;

                case "deleted":
                    await _registry.RemoveAsync(org, cancellationToken);
                    _logger.LogInformation("Removed installation for org {Org}", orgForLog);
                    break;
            }
        }
    }
}
