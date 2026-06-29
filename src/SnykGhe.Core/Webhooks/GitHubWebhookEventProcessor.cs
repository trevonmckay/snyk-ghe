using Octokit.Webhooks;
using Octokit.Webhooks.Events;
using Octokit.Webhooks.Events.CheckRun;
using Octokit.Webhooks.Events.Installation;
using Octokit.Webhooks.Events.PullRequest;
using SnykGhe.Core.Infrastructure;
using SnykGhe.Core.Processing;
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
        private readonly IGitHubInstallationRegistry _registry;
        private readonly ILogger _logger;

        public GitHubWebhookEventProcessor(
            PullRequestCheckService prCheckService,
            IGitHubInstallationRegistry registry,
            ILogger<GitHubWebhookEventProcessor> logger)
        {
            this._prCheckService = prCheckService;
            this._registry = registry;
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
        /// Re-runs a scan when a user clicks "Re-run" on the Snyk check run in a PR's Checks tab. GitHub
        /// delivers <c>check_run</c> with action <c>rerequested</c> only to the App that owns the check run,
        /// so this is always our own check. A check run with no associated pull request (e.g. a branch not
        /// in a PR) is ignored — this App only scans pull requests.
        /// </summary>
        protected override async ValueTask ProcessCheckRunWebhookAsync(
            WebhookHeaders headers,
            CheckRunEvent checkRunEvent,
            CheckRunAction action,
            CancellationToken cancellationToken = default)
        {
            if (checkRunEvent.Action is not string actionName ||
                !string.Equals(actionName, "rerequested", StringComparison.OrdinalIgnoreCase))
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
