using Snyk.Client;
using Snyk.Client.Resources;

namespace SnykGhe.Core.Snyk
{
    /// <summary>
    /// Removes the Snyk projects a merged/closed PR left behind. Each PR scan runs <c>snyk monitor</c> with
    /// <c>--target-reference=&lt;branch&gt;</c>, which publishes a branch reference under a <c>cli</c>-origin Snyk
    /// target for the repository; once GitHub deletes the branch, that reference is orphaned. This deletes the
    /// projects for a single branch reference across the repository's <c>cli</c> targets, and removes a target
    /// itself if that reference was its last. Best-effort: every failure (no org mapping, no credentials,
    /// target/project not found, any API error) is logged and swallowed.
    /// </summary>
    /// <remarks>
    /// Only <c>cli</c>-origin targets are touched. A repository imported through an SCM integration also has a
    /// separate integration target (e.g. <c>github-enterprise</c>); Snyk's integration owns that target's
    /// branches, so this app must not delete its projects. The two are also stored differently: <c>snyk
    /// monitor</c> normalizes the target url to the <c>http</c> scheme, whereas the branch scan and the SCM
    /// import use the <c>https</c> clone url — so a naive <c>?url=https://…</c> lookup finds only the SCM target
    /// and never the <c>cli</c> target holding the orphaned branch references.
    /// </remarks>
    public sealed class SnykProjectCleanupService
    {
        private const string CliIntegrationType = "cli";

        private readonly SnykApiClient _client;
        private readonly ILogger<SnykProjectCleanupService> _logger;

        public SnykProjectCleanupService(SnykApiClient client, ILogger<SnykProjectCleanupService> logger)
        {
            _client = client;
            _logger = logger;
        }

        /// <summary>
        /// Deletes every Snyk project whose target reference is <paramref name="branchReference"/> under the
        /// <c>cli</c> target(s) matching <paramref name="remoteRepoUrl"/>, then removes any such target that has
        /// no projects left. Returns the number of projects deleted (0 when nothing matched or cleanup is not
        /// configured).
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
                var targetIds = await FindCliTargetIdsAsync(snykOrgId!, remoteRepoUrl, cancellationToken);
                if (targetIds.Count == 0)
                {
                    _logger.LogInformation("No Snyk CLI target for {Repo}; nothing to clean up for branch {Ref}.", remoteRepoUrl, branchReference);
                    return 0;
                }

                var deleted = 0;
                foreach (var targetId in targetIds)
                {
                    var projects = await _client.Projects.ListAsync(
                        snykOrgId!,
                        new SnykProjectFilter { TargetId = targetId, TargetReference = branchReference },
                        cancellationToken);

                    if (projects.Count == 0)
                    {
                        continue;
                    }

                    var deletedHere = 0;
                    foreach (var project in projects)
                    {
                        if (await _client.Projects.DeleteAsync(snykOrgId!, project.Id, cancellationToken))
                        {
                            deleted++;
                            deletedHere++;
                        }
                    }

                    // If that was the target's last reference, the target is now an empty shell — remove it too.
                    // When default-branch monitoring is enabled the target keeps its default-branch reference, so
                    // this teardown does not fire for an actively-monitored repo — deleting a feature branch leaves
                    // the durable default-branch snapshot intact, which is the intended behavior.
                    if (deletedHere > 0 && !await TargetHasProjectsAsync(snykOrgId!, targetId, cancellationToken))
                    {
                        if (await _client.Targets.DeleteAsync(snykOrgId!, targetId, cancellationToken))
                        {
                            _logger.LogInformation("Removed empty Snyk target {TargetId} for {Repo} after deleting its last branch reference.", targetId, remoteRepoUrl);
                        }
                    }
                }

                if (deleted == 0)
                {
                    _logger.LogInformation("No Snyk projects for branch {Ref} on {Repo}; nothing to delete.", branchReference, remoteRepoUrl);
                }
                else
                {
                    _logger.LogInformation("Deleted {Count} Snyk project(s) for branch {Ref} on {Repo}.", deleted, branchReference, remoteRepoUrl);
                }

                return deleted;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Snyk cleanup for branch {Ref} on {Repo} did not complete.", branchReference, remoteRepoUrl);
                return 0;
            }
        }

        /// <summary>
        /// Finds the <c>cli</c>-origin target ids for <paramref name="remoteRepoUrl"/>. The Snyk <c>?url=</c>
        /// filter is scheme-sensitive and <c>snyk monitor</c> stores the target url under the <c>http</c> scheme,
        /// so both schemes are queried and the results filtered to <c>cli</c> targets whose url matches the
        /// repository scheme-insensitively — excluding SCM integration targets and any longer path that merely
        /// shares this prefix.
        /// </summary>
        private async Task<IReadOnlyList<string>> FindCliTargetIdsAsync(string orgId, string remoteRepoUrl, CancellationToken cancellationToken)
        {
            var wanted = NormalizeForMatch(remoteRepoUrl);
            var seen = new HashSet<string>(StringComparer.Ordinal);
            var ids = new List<string>();

            foreach (var candidateUrl in SchemeVariants(remoteRepoUrl))
            {
                var targets = await _client.Targets.ListAsync(orgId, candidateUrl, cancellationToken);
                foreach (var target in targets)
                {
                    if (!string.Equals(target.IntegrationType, CliIntegrationType, StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    if (!string.Equals(NormalizeForMatch(target.Url), wanted, StringComparison.Ordinal))
                    {
                        continue;
                    }

                    if (seen.Add(target.Id))
                    {
                        ids.Add(target.Id);
                    }
                }
            }

            return ids;
        }

        /// <summary>Yields the url as given plus its counterpart with the http/https scheme swapped.</summary>
        private static IEnumerable<string> SchemeVariants(string url)
        {
            yield return url;

            if (url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                yield return string.Concat("http://", url.AsSpan("https://".Length));
            }
            else if (url.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
            {
                yield return string.Concat("https://", url.AsSpan("http://".Length));
            }
        }

        /// <summary>Strips the scheme and any trailing slash and lower-cases, for scheme-insensitive url matching.</summary>
        private static string? NormalizeForMatch(string? url)
        {
            if (string.IsNullOrEmpty(url))
            {
                return url;
            }

            var value = url;
            if (value.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                value = value["https://".Length..];
            }
            else if (value.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
            {
                value = value["http://".Length..];
            }

            return value.TrimEnd('/').ToLowerInvariant();
        }

        private async Task<bool> TargetHasProjectsAsync(string orgId, string targetId, CancellationToken cancellationToken)
        {
            var projects = await _client.Projects.ListAsync(
                orgId, new SnykProjectFilter { TargetId = targetId }, cancellationToken);

            return projects.Count > 0;
        }
    }
}
