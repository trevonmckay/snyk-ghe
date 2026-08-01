using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using SnykGhe.Core.Configuration;
using SnykGhe.Core.GitHub;
using SnykGhe.Core.Infrastructure;
using SnykGhe.Core.Json;
using SnykGhe.Core.Storage;

namespace SnykGhe.Service.Controllers
{
    /// <summary>
    /// Full replacement of a GitHub org's policy overlay. Absent fields reset to their default (an unset
    /// mapping, no severity/ecosystem override, not suspended, no excludes). <c>SnykOrgId</c> is optional so
    /// an org can carry, for example, only an exclude list.
    /// </summary>
    [JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
    public sealed record OrgPolicyPutRequest
    {
        public string? SnykOrgId { get; init; }
        public string? SeverityThreshold { get; init; }
        public string? Ecosystem { get; init; }
        public bool? Suspended { get; init; }
        public List<string>? ExcludeDirs { get; init; }
    }

    /// <summary>
    /// Partial update of a GitHub org's policy overlay. Only specified fields change; an absent field is left
    /// unchanged, and an explicit null clears that override.
    /// </summary>
    [JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
    public sealed record OrgPolicyPatchRequest
    {
        public Optional<string?> SnykOrgId { get; init; }
        public Optional<string?> SeverityThreshold { get; init; }
        public Optional<string?> Ecosystem { get; init; }
        public Optional<bool> Suspended { get; init; }
        public Optional<List<string>?> ExcludeDirs { get; init; }
    }

    /// <summary>Full replacement of a repo's scan overrides. An absent or empty exclude list clears it.</summary>
    [JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
    public sealed record RepoConfigPutRequest
    {
        public List<string>? ExcludeDirs { get; init; }
    }

    /// <summary>Partial update of a repo's scan overrides. An absent exclude list is left unchanged.</summary>
    [JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
    public sealed record RepoConfigPatchRequest
    {
        public Optional<List<string>?> ExcludeDirs { get; init; }
    }

    /// <summary>
    /// Manages per-org Snyk mappings, policy overrides, and per-repo scan overrides. Guarded by an API key;
    /// front with Entra / Easy Auth in production.
    /// </summary>
    [ApiController]
    [Route("api/admin/orgs")]
    public sealed class AdminController : ControllerBase
    {
        private readonly IGitHubInstallationRegistry _registry;
        private readonly StorageOptions _options;
        private readonly ILogger<AdminController> _logger;

        public AdminController(
            IGitHubInstallationRegistry registry,
            IOptions<StorageOptions> options,
            ILogger<AdminController> logger)
        {
            _registry = registry;
            _options = options.Value;
            _logger = logger;
        }

        [HttpGet("{org}")]
        public async Task<IActionResult> Get(string org, CancellationToken cancellationToken)
        {
            if (!IsAuthorized())
            {
                return Unauthorized();
            }

            var record = await _registry.FindAsync(org, cancellationToken);
            return record is null ? NotFound() : Ok(OrgView(record));
        }

        [HttpPut("{org}")]
        public async Task<IActionResult> PutOrg(string org, [FromBody] OrgPolicyPutRequest body, CancellationToken cancellationToken)
        {
            if (!IsAuthorized())
            {
                return Unauthorized();
            }

            if (!TrySanitizeExcludes(body.ExcludeDirs, out var excludeDirs, out var error))
            {
                return BadRequest(error);
            }

            var overlay = new OrgPolicyOverlay
            {
                SnykOrgId = Clean(body.SnykOrgId),
                SeverityThreshold = Clean(body.SeverityThreshold),
                Ecosystem = Clean(body.Ecosystem),
                Suspended = body.Suspended ?? false,
                ExcludeDirs = excludeDirs,
            };

            await _registry.SetOrgPolicyAsync(org, overlay, cancellationToken);
            _logger.LogInformation("Replaced Snyk policy for org {Org}", LogSanitizer.Clean(org));
            return Ok(OrgView(org, overlay));
        }

        [HttpPatch("{org}")]
        public async Task<IActionResult> PatchOrg(string org, [FromBody] OrgPolicyPatchRequest body, CancellationToken cancellationToken)
        {
            if (!IsAuthorized())
            {
                return Unauthorized();
            }

            var record = await _registry.FindAsync(org, cancellationToken);
            if (record is null)
            {
                return NotFound();
            }

            var overlay = new OrgPolicyOverlay
            {
                SnykOrgId = record.SnykOrgId,
                SeverityThreshold = record.SeverityThreshold,
                Ecosystem = record.Ecosystem,
                Suspended = record.Suspended,
                ExcludeDirs = record.ExcludeDirs,
            };

            if (body.SnykOrgId.IsSpecified)
            {
                overlay.SnykOrgId = Clean(body.SnykOrgId.Value);
            }

            if (body.SeverityThreshold.IsSpecified)
            {
                overlay.SeverityThreshold = Clean(body.SeverityThreshold.Value);
            }

            if (body.Ecosystem.IsSpecified)
            {
                overlay.Ecosystem = Clean(body.Ecosystem.Value);
            }

            if (body.Suspended.IsSpecified)
            {
                overlay.Suspended = body.Suspended.Value;
            }

            if (body.ExcludeDirs.IsSpecified)
            {
                if (!TrySanitizeExcludes(body.ExcludeDirs.Value, out var excludeDirs, out var error))
                {
                    return BadRequest(error);
                }

                overlay.ExcludeDirs = excludeDirs;
            }

            await _registry.SetOrgPolicyAsync(org, overlay, cancellationToken);
            _logger.LogInformation("Updated Snyk policy for org {Org}", LogSanitizer.Clean(org));
            return Ok(OrgView(org, overlay));
        }

        [HttpGet("{org}/repos/{repo}")]
        public async Task<IActionResult> GetRepo(string org, string repo, CancellationToken cancellationToken)
        {
            if (!IsAuthorized())
            {
                return Unauthorized();
            }

            var config = await _registry.FindRepoConfigAsync(org, repo, cancellationToken);
            return config is null ? NotFound() : Ok(RepoView(config.GitHubOrg, config.Repo, config.ExcludeDirs));
        }

        [HttpPut("{org}/repos/{repo}")]
        public async Task<IActionResult> PutRepo(string org, string repo, [FromBody] RepoConfigPutRequest body, CancellationToken cancellationToken)
        {
            if (!IsAuthorized())
            {
                return Unauthorized();
            }

            if (!TrySanitizeExcludes(body.ExcludeDirs, out var excludeDirs, out var error))
            {
                return BadRequest(error);
            }

            await _registry.SetRepoConfigAsync(org, repo, excludeDirs, cancellationToken);
            _logger.LogInformation("Replaced scan config for {Org}/{Repo}", LogSanitizer.Clean(org), LogSanitizer.Clean(repo));
            return Ok(RepoView(org, repo, excludeDirs));
        }

        [HttpPatch("{org}/repos/{repo}")]
        public async Task<IActionResult> PatchRepo(string org, string repo, [FromBody] RepoConfigPatchRequest body, CancellationToken cancellationToken)
        {
            if (!IsAuthorized())
            {
                return Unauthorized();
            }

            var config = await _registry.FindRepoConfigAsync(org, repo, cancellationToken);
            if (config is null)
            {
                return NotFound();
            }

            var excludeDirs = config.ExcludeDirs;
            if (body.ExcludeDirs.IsSpecified)
            {
                if (!TrySanitizeExcludes(body.ExcludeDirs.Value, out var sanitized, out var error))
                {
                    return BadRequest(error);
                }

                excludeDirs = sanitized;
            }

            await _registry.SetRepoConfigAsync(org, repo, excludeDirs, cancellationToken);
            _logger.LogInformation("Updated scan config for {Org}/{Repo}", LogSanitizer.Clean(org), LogSanitizer.Clean(repo));
            return Ok(RepoView(org, repo, excludeDirs));
        }

        [HttpDelete("{org}/repos/{repo}")]
        public async Task<IActionResult> DeleteRepo(string org, string repo, CancellationToken cancellationToken)
        {
            if (!IsAuthorized())
            {
                return Unauthorized();
            }

            await _registry.RemoveRepoConfigAsync(org, repo, cancellationToken);
            _logger.LogInformation("Removed scan config for {Org}/{Repo}", LogSanitizer.Clean(org), LogSanitizer.Clean(repo));
            return NoContent();
        }

        /// <summary>
        /// Rejects path-like exclude entries (400) and returns the sanitized list. A path in <c>--exclude</c>
        /// errors the CLI and fails the whole scan, so it must never reach storage.
        /// </summary>
        private static bool TrySanitizeExcludes(IReadOnlyList<string>? raw, out IReadOnlyList<string> sanitized, out string? error)
        {
            if (raw is not null)
            {
                var offending = raw
                    .Where(e => !string.IsNullOrWhiteSpace(e) && ExcludeList.IsPathLike(e.Trim()))
                    .ToList();

                if (offending.Count > 0)
                {
                    sanitized = [];
                    error = $"excludeDirs must be directory/file names, not paths. Offending: {string.Join(", ", offending)}";
                    return false;
                }
            }

            sanitized = ExcludeList.Sanitize(raw);
            error = null;
            return true;
        }

        private static string? Clean(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

        private static object OrgView(GitHubInstallationRecord record) => new
        {
            record.GitHubOrg,
            record.InstallationId,
            record.SnykOrgId,
            record.SeverityThreshold,
            record.Ecosystem,
            record.Suspended,
            record.ExcludeDirs,
        };

        private static object OrgView(string org, OrgPolicyOverlay overlay) => new
        {
            GitHubOrg = org,
            overlay.SnykOrgId,
            overlay.SeverityThreshold,
            overlay.Ecosystem,
            overlay.Suspended,
            overlay.ExcludeDirs,
        };

        private static object RepoView(string org, string repo, IReadOnlyList<string> excludeDirs) => new
        {
            GitHubOrg = org,
            Repo = repo,
            ExcludeDirs = excludeDirs,
        };

        private bool IsAuthorized() =>
            AdminApiKeyGuard.Matches(Request.Headers["X-Admin-Key"].FirstOrDefault(), _options.AdminApiKey);
    }
}
