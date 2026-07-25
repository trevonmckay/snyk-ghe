using Microsoft.Extensions.Options;
using Snyk.Client;
using Snyk.Client.Tests;
using SnykGhe.Core.Configuration;
using SnykScannerKind = Snyk.Client.Tests.SnykScanner;

namespace SnykGhe.Core.Snyk
{
    /// <summary>
    /// Runs Snyk Code (SAST) through the Test REST API. The API reads the source itself through a Snyk SCM
    /// integration rather than from our working copy, so the repository must already be imported into Snyk
    /// under that integration. A repository whose only Snyk target was created by <c>snyk monitor</c> is not
    /// imported in that sense, and Snyk answers <c>SNYK-TARGET-0001: Target not found</c>.
    /// </summary>
    public sealed class ApiCodeScanner : ICodeScanner
    {
        /// <summary>Snyk's error code for a repository the configured integration cannot resolve.</summary>
        private const string TargetNotFoundCode = "SNYK-TARGET-0001";

        private readonly SnykApiClient _client;
        private readonly SnykOptions _options;
        private readonly ILogger<ApiCodeScanner> _logger;

        public ApiCodeScanner(SnykApiClient client, IOptions<SnykOptions> options, ILogger<ApiCodeScanner> logger)
        {
            _client = client;
            _options = options.Value;
            _logger = logger;
        }

        public async Task<ProductScanResult> ScanAsync(ScanContext context, CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(context.Policy.SnykOrgId))
            {
                return ProductScanResult.Fail(SnykProduct.Code, "No Snyk org is mapped for this GitHub org; the Snyk Code API scan cannot run.");
            }

            if (string.IsNullOrWhiteSpace(_options.ScmIntegrationId))
            {
                return ProductScanResult.Fail(SnykProduct.Code,
                    "Snyk:ScmIntegrationId is not configured; the Snyk Code API scan needs an SCM integration to read the repository.");
            }

            var request = new SnykTestRequest
            {
                Resources =
                [
                    new ScmRepositoryResource
                    {
                        RepositoryUrl = context.RemoteRepoUrl,
                        IntegrationId = _options.ScmIntegrationId!,
                        Reference = context.TargetReference,
                    },
                ],
                Scanners = [SnykScannerKind.Sast],
                Stage = SdlcStage.PrCheck,
                Configuration = new SnykTestConfiguration
                {
                    // Requesting publication errors the whole test rather than degrading it, so this scan never
                    // asks for it and SnykMonitor publishes instead. Snyk rejects target_name/target_reference on
                    // an SCM resource outright ("Project name configuration or target configuration is not
                    // possible for a git URL input" — its flow is named `sast_scm_stateless`), and publish_report
                    // alone fails with SNYK-9999 "failed to create project ... got [400] status".
                    PublishReport = false,
                },
            };

            SnykTestRun run;
            try
            {
                run = await _client.Tests.RunAsync(context.Policy.SnykOrgId!, request, cancellationToken);
            }
            catch (SnykApiException ex)
            {
                _logger.LogWarning(ex, "Snyk Code API test failed for {Repo} (request-id {RequestId}).", context.RemoteRepoUrl, ex.RequestId);
                return ProductScanResult.Fail(SnykProduct.Code, ex.Message);
            }

            if (!run.Test.Succeeded)
            {
                return FromFailedTest(run.Test, context);
            }

            var findings = run.Findings.Select(ToFinding).ToList();
            return new ProductScanResult { Product = SnykProduct.Code, Findings = findings };
        }

        /// <summary>
        /// Translates a test that never ran. A repository the integration cannot see is a configuration gap
        /// rather than a scan failure, so it is surfaced as a non-blocking neutral check naming the cause
        /// instead of a silent skip.
        /// </summary>
        private ProductScanResult FromFailedTest(SnykTest test, ScanContext context)
        {
            var targetNotFound = test.Errors.Any(
                e => string.Equals(e.Code, TargetNotFoundCode, StringComparison.OrdinalIgnoreCase));

            if (targetNotFound)
            {
                _logger.LogWarning("Snyk has no SCM target for {Repo}; import it into Snyk to scan Code through the API.", context.RemoteRepoUrl);
                return ProductScanResult.Fail(SnykProduct.Code,
                    $"Snyk could not find `{context.RemoteRepoUrl}` under the configured SCM integration. " +
                    "Import the repository into Snyk, or run the Code scan on the CLI engine.");
            }

            _logger.LogWarning("Snyk Code API test {TestId} did not complete (request-id {RequestId}): {Errors}",
                test.Id, test.RequestId, test.ErrorSummary);
            return ProductScanResult.Fail(SnykProduct.Code, test.ErrorSummary);
        }

        private static SnykFinding ToFinding(SnykTestFinding finding) => new()
        {
            Severity = finding.Severity,
            Title = finding.Title,
            Location = BuildLocation(finding),
        };

        private static string? BuildLocation(SnykTestFinding finding)
        {
            if (string.IsNullOrWhiteSpace(finding.FilePath))
            {
                return null;
            }

            return finding.StartLine is { } line ? $"{finding.FilePath}:{line}" : finding.FilePath;
        }
    }
}
