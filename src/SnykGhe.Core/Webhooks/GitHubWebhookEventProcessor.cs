using Octokit.Webhooks;
using Octokit.Webhooks.Events;
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

        private static readonly HashSet<string> ScanTriggeringActions =
            new(StringComparer.OrdinalIgnoreCase) { "opened", "synchronize", "reopened" };

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

            if (pullRequestEvent.Installation is null ||
                pullRequestEvent.Repository is { CloneUrl: null } or null)
            {
                _logger.LogWarning("Pull request event missing installation or repository clone URL; ignoring.");
                return;
            }

            var request = new ScanRequest
            {
                InstallationId = pullRequestEvent.Installation.Id,
                Owner = pullRequestEvent.Repository.Owner.Login,
                Repo = pullRequestEvent.Repository.Name,
                CloneUrl = pullRequestEvent.Repository.CloneUrl,
                PrNumber = (int)pullRequestEvent.Number,
                HeadRef = pullRequestEvent.PullRequest.Head.Ref,
                HeadSha = pullRequestEvent.PullRequest.Head.Sha,
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
