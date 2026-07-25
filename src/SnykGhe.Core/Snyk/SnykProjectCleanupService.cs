using Snyk.Client;
using Snyk.Client.Resources;

namespace SnykGhe.Core.Snyk
{
    /// <summary>
    /// Removes the Snyk projects a merged/closed PR left behind. Each PR scan runs <c>snyk monitor</c> with
    /// <c>--target-reference=&lt;branch&gt;</c>, which publishes a branch reference under the repository's Snyk
    /// target; once GitHub deletes the branch, that reference is orphaned. This deletes the projects for a
    /// single branch reference (scoped to the repository's target so a same-named branch in another repo is
    /// untouched), and removes the target itself if that reference was its last. Best-effort: every failure
    /// (no org mapping, no credentials, target/project not found, any API error) is logged and swallowed.
    /// </summary>
    public sealed class SnykProjectCleanupService
    {
        private readonly SnykApiClient _client;
        private readonly ILogger<SnykProjectCleanupService> _logger;

        public SnykProjectCleanupService(SnykApiClient client, ILogger<SnykProjectCleanupService> logger)
        {
            _client = client;
            _logger = logger;
        }

        /// <summary>
        /// Deletes every Snyk project whose target reference is <paramref name="branchReference"/> under the
        /// target matching <paramref name="remoteRepoUrl"/>, then removes the target if it has no projects left.
        /// Returns the number of projects deleted (0 when nothing matched or cleanup is not configured).
        /// </summary>
        public async Task<int> DeleteBranchProjectsAsync(
            string? snykOrgId,
            string remoteRepoUrl,
            string branchReference,
            CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(snykOrgId) || string.IsNullOrWhiteSpace(branchReference))
            {
                return 0;
            }

            try
            {
                var targetId = await FindTargetIdAsync(snykOrgId!, remoteRepoUrl, cancellationToken);
                if (targetId is null)
                {
                    _logger.LogInformation("No Snyk target for {Repo}; nothing to clean up for branch {Ref}.", remoteRepoUrl, branchReference);
                    return 0;
                }

                var projects = await _client.Projects.ListAsync(
                    snykOrgId!,
                    new SnykProjectFilter { TargetId = targetId, TargetReference = branchReference },
                    cancellationToken);

                if (projects.Count == 0)
                {
                    _logger.LogInformation("No Snyk projects for branch {Ref} on {Repo}; nothing to delete.", branchReference, remoteRepoUrl);
                    return 0;
                }

                var deleted = 0;
                foreach (var project in projects)
                {
                    if (await _client.Projects.DeleteAsync(snykOrgId!, project.Id, cancellationToken))
                    {
                        deleted++;
                    }
                }

                _logger.LogInformation("Deleted {Count} Snyk project(s) for branch {Ref} on {Repo}.", deleted, branchReference, remoteRepoUrl);

                // If that was the target's last reference, the target is now an empty shell — remove it too.
                // When default-branch monitoring is enabled the target keeps its default-branch reference, so
                // this teardown does not fire for an actively-monitored repo — deleting a feature branch leaves
                // the durable default-branch snapshot intact, which is the intended behavior.
                if (deleted > 0 && !await TargetHasProjectsAsync(snykOrgId!, targetId, cancellationToken))
                {
                    if (await _client.Targets.DeleteAsync(snykOrgId!, targetId, cancellationToken))
                    {
                        _logger.LogInformation("Removed empty Snyk target for {Repo} after deleting its last branch reference.", remoteRepoUrl);
                    }
                }

                return deleted;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Snyk cleanup for branch {Ref} on {Repo} did not complete.", branchReference, remoteRepoUrl);
                return 0;
            }
        }

        private async Task<string?> FindTargetIdAsync(string orgId, string remoteRepoUrl, CancellationToken cancellationToken)
        {
            var targets = await _client.Targets.ListAsync(orgId, remoteRepoUrl, cancellationToken);

            // The server-side url filter is a match, not necessarily exact; prefer the target whose url is
            // identical so a longer repo path that shares this prefix cannot be cleaned up by mistake.
            var exact = targets.FirstOrDefault(
                t => string.Equals(t.Url, remoteRepoUrl, StringComparison.OrdinalIgnoreCase));

            return exact?.Id ?? targets.FirstOrDefault()?.Id;
        }

        private async Task<bool> TargetHasProjectsAsync(string orgId, string targetId, CancellationToken cancellationToken)
        {
            var projects = await _client.Projects.ListAsync(
                orgId, new SnykProjectFilter { TargetId = targetId }, cancellationToken);

            return projects.Count > 0;
        }
    }
}
