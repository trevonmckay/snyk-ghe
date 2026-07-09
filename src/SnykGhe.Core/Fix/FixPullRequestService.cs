using System.Text;
using Microsoft.Extensions.Options;
using Octokit;
using SnykGhe.Core.Configuration;
using SnykGhe.Core.Processing;
using SnykGhe.Core.Snyk;

namespace SnykGhe.Core.Fix
{
    /// <summary>
    /// Opens a remediation pull request: patches manifests for the org's ecosystem, commits the changes
    /// as the App's bot identity via the Contents API, and targets the contributor's branch so the fix
    /// can be merged into their PR.
    /// </summary>
    public sealed class FixPullRequestService
    {
        private readonly FixPlanner _planner;
        private readonly Dictionary<string, IManifestPatcher> _patchers;
        private readonly SnykOptions _options;
        private readonly ILogger<FixPullRequestService> _logger;

        public FixPullRequestService(
            FixPlanner planner,
            IEnumerable<IManifestPatcher> patchers,
            IOptions<SnykOptions> snykOptions,
            ILogger<FixPullRequestService> logger)
        {
            _planner = planner;
            _patchers = patchers.ToDictionary(p => p.Ecosystem, StringComparer.OrdinalIgnoreCase);
            _options = snykOptions.Value;
            _logger = logger;
        }

        public async Task TryOpenAsync(
            ScanRequest request,
            ResolvedPolicy policy,
            SnykScanResult scan,
            GitHubClient client,
            string workingDirectory,
            CancellationToken cancellationToken)
        {
            if (!_options.OpenFixPullRequests)
            {
                return;
            }

            var plan = _planner.Plan(scan);
            if (!plan.HasUpgrades)
            {
                return;
            }

            if (!_patchers.TryGetValue(policy.Ecosystem, out var patcher))
            {
                _logger.LogInformation("No manifest patcher for ecosystem '{Ecosystem}'; skipping fix PR.", policy.Ecosystem);
                return;
            }

            var patched = patcher.Apply(workingDirectory, plan);
            if (patched.Count == 0)
            {
                _logger.LogInformation("Upgrades available but no matching manifests changed for {Owner}/{Repo}.", request.Owner, request.Repo);
                return;
            }

            var branch = $"snyk-fix/pr-{request.PrNumber}-{request.HeadSha[..7]}";
            await EnsureBranchAsync(client, request, branch, cancellationToken);

            foreach (var file in patched)
            {
                var existing = await client.Repository.Content.GetAllContentsByRef(request.Owner, request.Repo, file.RelativePath, branch);
                await client.Repository.Content.UpdateFile(request.Owner, request.Repo, file.RelativePath,
                    new UpdateFileRequest(
                        message: $"fix: upgrade vulnerable NuGet packages in {file.RelativePath}",
                        content: file.NewContent,
                        sha: existing[0].Sha,
                        branch: branch));
            }

            var pr = await client.PullRequest.Create(request.Owner, request.Repo,
                new NewPullRequest($"[Snyk] Upgrade {plan.Upgrades.Count} vulnerable package(s)", branch, request.HeadRef)
                {
                    Body = BuildBody(plan),
                });

            _logger.LogInformation("Opened fix PR #{Number} targeting {Owner}/{Repo}:{Base}", pr.Number, request.Owner, request.Repo, request.HeadRef);
        }

        private static async Task EnsureBranchAsync(GitHubClient client, ScanRequest request, string branch, CancellationToken cancellationToken)
        {
            try
            {
                await client.Git.Reference.Create(request.Owner, request.Repo,
                    new NewReference($"refs/heads/{branch}", request.HeadSha));
            }
            catch (ApiValidationException)
            {
                // Branch already exists from an earlier run on this PR; point it at the latest head.
                await client.Git.Reference.Update(request.Owner, request.Repo, $"heads/{branch}",
                    new ReferenceUpdate(request.HeadSha, force: true));
            }
        }

        private static string BuildBody(FixPlan plan)
        {
            var sb = new StringBuilder();
            sb.AppendLine("Automated dependency upgrades to resolve Snyk-detected vulnerabilities.");
            sb.AppendLine();
            sb.AppendLine("| Package | From | To | Fixes |");
            sb.AppendLine("| --- | --- | --- | --- |");
            foreach (var u in plan.Upgrades)
            {
                sb.AppendLine($"| {u.PackageName} | {u.FromVersion} | {u.ToVersion} | {string.Join(", ", u.VulnerabilityIds)} |");
            }

            return sb.ToString();
        }
    }
}
