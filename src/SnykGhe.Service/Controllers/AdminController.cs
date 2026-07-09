using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using SnykGhe.Core.Configuration;
using SnykGhe.Core.Infrastructure;
using SnykGhe.Core.Storage;

namespace SnykGhe.Service.Controllers
{
    /// <summary>Request body for setting a GitHub org's explicit Snyk mapping.</summary>
    public sealed record OrgMappingRequest
    {
        public string SnykOrgId { get; init; } = string.Empty;
        public string? SeverityThreshold { get; init; }
        public string? Ecosystem { get; init; }
    }

    /// <summary>
    /// Sets the explicit Snyk org mapping and policy overrides per GitHub org. Guarded by an API key;
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

        [HttpPut("{org}")]
        public async Task<IActionResult> SetMapping(string org, [FromBody] OrgMappingRequest body, CancellationToken cancellationToken)
        {
            if (!IsAuthorized())
            {
                return Unauthorized();
            }

            if (string.IsNullOrWhiteSpace(body.SnykOrgId))
            {
                return BadRequest("SnykOrgId is required.");
            }

            await _registry.SetMappingAsync(org, body.SnykOrgId, body.SeverityThreshold, body.Ecosystem, cancellationToken);
            _logger.LogInformation("Set Snyk mapping for org {Org}", LogSanitizer.Clean(org));
            return NoContent();
        }

        [HttpGet("{org}")]
        public async Task<IActionResult> Get(string org, CancellationToken cancellationToken)
        {
            if (!IsAuthorized())
            {
                return Unauthorized();
            }

            var record = await _registry.FindAsync(org, cancellationToken);
            return record is null
                ? NotFound()
                : Ok(new
                {
                    record.GitHubOrg,
                    record.InstallationId,
                    record.SnykOrgId,
                    record.SeverityThreshold,
                    record.Ecosystem,
                    record.Suspended,
                });
        }

        private bool IsAuthorized() =>
            AdminApiKeyGuard.Matches(Request.Headers["X-Admin-Key"].FirstOrDefault(), _options.AdminApiKey);
    }
}
