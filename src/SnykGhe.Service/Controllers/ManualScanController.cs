using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.Extensions.Options;
using Octokit;
using SnykGhe.Core.Configuration;
using SnykGhe.Core.GitHub;
using SnykGhe.Core.Infrastructure;
using SnykGhe.Core.Processing;
using SnykGhe.Core.Storage;

namespace SnykGhe.Service.Controllers
{
    /// <summary>Request body for a manual baseline scan. Omit the body (or the branch) to scan the default branch.</summary>
    public sealed record ManualScanRequest
    {
        /// <summary>Branch to scan; defaults to the repository's default branch when null or empty.</summary>
        public string? Branch { get; init; }
    }

    /// <summary>
    /// Manually triggers a baseline scan of a repository branch. Enqueues the scan onto the same durable
    /// queue and processing path as an automatic push (default branch on merge). Guarded by the admin API
    /// key; front with Entra / Easy Auth in production.
    /// </summary>
    [ApiController]
    [Route("api/admin/scans")]
    public sealed class ManualScanController : ControllerBase
    {
        private readonly IGitHubInstallationRegistry _registry;
        private readonly GitHubClientFactory _clientFactory;
        private readonly IWebhookQueue _queue;
        private readonly StorageOptions _options;
        private readonly ILogger<ManualScanController> _logger;

        public ManualScanController(
            IGitHubInstallationRegistry registry,
            GitHubClientFactory clientFactory,
            IWebhookQueue queue,
            IOptions<StorageOptions> options,
            ILogger<ManualScanController> logger)
        {
            _registry = registry;
            _clientFactory = clientFactory;
            _queue = queue;
            _options = options.Value;
            _logger = logger;
        }

        /// <summary>
        /// Queues a baseline scan for <paramref name="org"/>/<paramref name="repo"/>. Scans the repository's
        /// default branch unless the request body overrides the branch. Returns 202 once queued; the scan
        /// runs in the background and results surface in the Snyk Web UI and logs.
        /// </summary>
        [HttpPost("{org}/{repo}")]
        public async Task<IActionResult> Trigger(
            string org,
            string repo,
            [FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] ManualScanRequest? body,
            CancellationToken cancellationToken)
        {
            if (!AdminApiKeyGuard.Matches(Request.Headers["X-Admin-Key"].FirstOrDefault(), _options.AdminApiKey))
            {
                return Unauthorized();
            }

            var record = await _registry.FindAsync(org, cancellationToken);
            if (record is null)
            {
                return NotFound($"No GitHub App installation is registered for org '{org}'.");
            }

            if (record.Suspended)
            {
                return Conflict($"The GitHub App installation for org '{org}' is suspended.");
            }

            var credentials = await _clientFactory.CreateInstallationClientAsync(record.InstallationId, cancellationToken);

            Repository repository;
            try
            {
                repository = await credentials.Client.Repository.Get(org, repo);
            }
            catch (NotFoundException)
            {
                return NotFound($"Repository '{org}/{repo}' was not found or the installation cannot access it.");
            }

            var branchToScan = string.IsNullOrWhiteSpace(body?.Branch) ? repository.DefaultBranch : body.Branch;

            Branch resolvedBranch;
            try
            {
                resolvedBranch = await credentials.Client.Repository.Branch.Get(org, repo, branchToScan);
            }
            catch (NotFoundException)
            {
                return NotFound($"Branch '{branchToScan}' was not found on '{org}/{repo}'.");
            }

            var scanRequest = new BaselineScanRequest
            {
                InstallationId = record.InstallationId,
                Owner = org,
                Repo = repo,
                CloneUrl = repository.CloneUrl,
                Branch = branchToScan,
                HeadSha = resolvedBranch.Commit.Sha,
            };

            await _queue.EnqueueAsync(
                new GitHubWebhookMessage
                {
                    Body = BaselineScanMessage.Serialize(scanRequest),
                    EventName = BaselineScanMessage.EventName,
                    DeliveryId = $"manual-{Guid.NewGuid():N}",
                },
                cancellationToken);

            _logger.LogInformation("Queued manual baseline scan for {Repo} branch {Branch}",
                LogSanitizer.Clean(repository.FullName), LogSanitizer.Clean(branchToScan));

            return Accepted(new { org, repo, branch = branchToScan, status = "queued" });
        }
    }
}
