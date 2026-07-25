using Snyk.Client;
using Snyk.Client.Tests;
using SnykScannerKind = Snyk.Client.Tests.SnykScanner;

namespace SnykGhe.Core.Snyk
{
    /// <summary>
    /// Scans dependencies through the Snyk Test REST API instead of the CLI, by submitting the working copy's
    /// dependency graphs as inline resources.
    ///
    /// Results are mapped back onto <see cref="SnykScanResult"/> — the same shape the CLI produces — so the
    /// fix-PR planner and Check Run rendering are unaware of which engine ran.
    /// </summary>
    public sealed class ApiOpenSourceScanner : IOpenSourceScanner
    {
        private readonly SnykApiClient _client;
        private readonly DepGraphGenerator _depGraphs;
        private readonly ILogger<ApiOpenSourceScanner> _logger;

        public ApiOpenSourceScanner(SnykApiClient client, DepGraphGenerator depGraphs, ILogger<ApiOpenSourceScanner> logger)
        {
            _client = client;
            _depGraphs = depGraphs;
            _logger = logger;
        }

        public async Task<SnykScanResult> ScanAsync(ScanContext context, CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(context.Policy.SnykOrgId))
            {
                return Failed("No Snyk org is mapped for this GitHub org; the Snyk API scan cannot run.");
            }

            var depGraphs = await _depGraphs.GenerateAsync(context, cancellationToken);

            // A generator failure must not be reported as a clean scan: nothing was tested.
            if (depGraphs.Failed)
            {
                return Failed(depGraphs.FailureMessage ?? "Could not build dependency graphs for the Snyk API scan.");
            }

            if (depGraphs.Graphs.Count == 0)
            {
                _logger.LogInformation("No dependency graphs produced for {Dir}; nothing for the Snyk API to scan.", context.WorkingDirectory);
                return new SnykScanResult { Projects = [] };
            }

            // Each manifest is tested on its own so a per-project result can be reported, mirroring the CLI's
            // --all-projects output. One manifest failing does not discard the others.
            var projects = new List<SnykProjectResult>(depGraphs.Graphs.Count);

            foreach (var graph in depGraphs.Graphs)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var request = new SnykTestRequest
                {
                    Resources =
                    [
                        new InlineDepGraphResource
                        {
                            Name = graph.Name,
                            DepGraph = graph.Graph,
                            ScmContext = new SnykScmContext
                            {
                                RepositoryUrl = context.RemoteRepoUrl,
                                Branch = context.TargetReference,
                            },
                        },
                    ],
                    Scanners = [SnykScannerKind.Sca],
                    Stage = SdlcStage.PrCheck,
                    Configuration = new SnykTestConfiguration
                    {
                        // Publishing is done by SnykMonitor; a test here must not create projects of its own.
                        PublishReport = false,
                    },
                };

                try
                {
                    var run = await _client.Tests.RunAsync(context.Policy.SnykOrgId!, request, cancellationToken);

                    if (!run.Test.Succeeded)
                    {
                        _logger.LogWarning("Snyk API test for {Manifest} did not complete: {Errors}", graph.Name, run.Test.ErrorSummary);
                        return Failed(run.Test.ErrorSummary);
                    }

                    projects.Add(SnykApiFindingMapper.ToProjectResult(graph.Name, run.Findings));
                }
                catch (SnykApiException ex)
                {
                    _logger.LogWarning(ex, "Snyk API test for {Manifest} failed.", graph.Name);
                    return Failed(ex.Message);
                }
            }

            return new SnykScanResult { Projects = projects };
        }

        private static SnykScanResult Failed(string message) =>
            new() { Projects = [], Failed = true, FailureMessage = message };
    }
}
