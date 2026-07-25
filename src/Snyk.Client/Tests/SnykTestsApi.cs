using System.Diagnostics;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;

namespace Snyk.Client.Tests
{
    /// <summary>Status of an in-flight or completed test job.</summary>
    public sealed class SnykTestJob
    {
        public required string JobId { get; init; }

        /// <summary>Set once the job completes and the API redirects to the resulting test.</summary>
        public string? TestId { get; init; }

        public bool IsComplete => TestId is not null;
    }

    /// <summary>
    /// The Snyk Test API (Early Access): submit content for scanning, then read the resulting test and its
    /// findings.
    ///
    /// Creation is asynchronous. <c>POST /tests</c> answers <c>202</c> with a test-job id for virtually any
    /// well-formed body — including combinations of scanner and resource that Snyk cannot actually run — so a
    /// <c>202</c> does not mean the scan will happen. Incompatibility surfaces only once the job completes,
    /// as a test whose execution state is <c>errored</c>. Callers must inspect <see cref="SnykTest.Succeeded"/>.
    /// </summary>
    public sealed class SnykTestsApi
    {
        // A completed job answers 303 with a Location of /rest/orgs/{org}/tests/{test_id}?version=...
        private static readonly Regex TestIdPattern = new(
            @"/tests/(?<id>[0-9a-fA-F-]{36})", RegexOptions.Compiled | RegexOptions.CultureInvariant);

        private readonly SnykHttpTransport _transport;
        private readonly ILogger _logger;

        internal SnykTestsApi(SnykHttpTransport transport, ILogger logger)
        {
            _transport = transport;
            _logger = logger;
        }

        /// <summary>Submits a test and returns the id of the job that will produce it.</summary>
        public async Task<string> CreateAsync(string orgId, SnykTestRequest request, CancellationToken cancellationToken = default)
        {
            var url = _transport.BuildUrl($"/orgs/{Uri.EscapeDataString(orgId)}/tests");

            using var doc = await _transport.PostAsync(url, request.ToJson(), cancellationToken);
            var jobId = doc.RootElement.GetProperty("data").GetProperty("id").GetString();

            return string.IsNullOrWhiteSpace(jobId)
                ? throw new SnykApiException("Snyk accepted the test but returned no job id.")
                : jobId;
        }

        /// <summary>
        /// Polls a test job once. While the job runs the API answers 200 with its status; once finished it
        /// answers 303 pointing at the test resource, which is the only place the test id is published.
        /// </summary>
        public async Task<SnykTestJob> GetJobAsync(string orgId, string jobId, CancellationToken cancellationToken = default)
        {
            var url = _transport.BuildUrl($"/orgs/{Uri.EscapeDataString(orgId)}/test_jobs/{Uri.EscapeDataString(jobId)}");

            var location = await _transport.GetRedirectLocationAsync(url, cancellationToken);
            if (location is null)
            {
                return new SnykTestJob { JobId = jobId };
            }

            var match = TestIdPattern.Match(location);
            if (!match.Success)
            {
                throw new SnykApiException($"Snyk redirected test job {jobId} to an unrecognized location '{location}'.");
            }

            return new SnykTestJob { JobId = jobId, TestId = match.Groups["id"].Value };
        }

        /// <summary>Reads a test resource, whether it finished or errored.</summary>
        public async Task<SnykTest> GetAsync(string orgId, string testId, CancellationToken cancellationToken = default)
        {
            var url = _transport.BuildUrl($"/orgs/{Uri.EscapeDataString(orgId)}/tests/{Uri.EscapeDataString(testId)}");

            using var doc = await _transport.GetAsync(url, cancellationToken);
            return TestResultParser.ParseTest(doc.RootElement.GetProperty("data"));
        }

        /// <summary>Reads every finding of a completed test, following pagination.</summary>
        public async Task<IReadOnlyList<SnykTestFinding>> GetFindingsAsync(string orgId, string testId, CancellationToken cancellationToken = default)
        {
            var url = _transport.BuildUrl(
                $"/orgs/{Uri.EscapeDataString(orgId)}/tests/{Uri.EscapeDataString(testId)}/findings",
                ("limit", _transport.Options.PageSize.ToString()));

            var items = await _transport.GetPagedAsync(url, cancellationToken);

            var findings = new List<SnykTestFinding>(items.Count);
            foreach (var item in items)
            {
                findings.Add(TestResultParser.ParseFinding(item));
            }

            return findings;
        }

        /// <summary>Waits for a job to complete, then returns the resulting test (which may have errored).</summary>
        public async Task<SnykTest> WaitAsync(string orgId, string jobId, CancellationToken cancellationToken = default)
        {
            var deadline = Stopwatch.StartNew();

            while (true)
            {
                var job = await GetJobAsync(orgId, jobId, cancellationToken);
                if (job.TestId is not null)
                {
                    return await GetAsync(orgId, job.TestId, cancellationToken);
                }

                if (deadline.Elapsed > _transport.Options.TestTimeout)
                {
                    throw new SnykApiException(
                        $"Snyk test job {jobId} did not complete within {_transport.Options.TestTimeout.TotalMinutes:0} minutes.");
                }

                await Task.Delay(_transport.Options.TestPollInterval, cancellationToken);
            }
        }

        /// <summary>
        /// Creates a test, waits for it, and reads its findings. Findings are fetched only for a test that
        /// finished; an errored test carries none and its <see cref="SnykTest.Errors"/> explain why.
        /// </summary>
        public async Task<SnykTestRun> RunAsync(string orgId, SnykTestRequest request, CancellationToken cancellationToken = default)
        {
            var jobId = await CreateAsync(orgId, request, cancellationToken);
            _logger.LogDebug("Snyk test job {JobId} created in org {OrgId}.", jobId, orgId);

            var test = await WaitAsync(orgId, jobId, cancellationToken);

            if (!test.Succeeded)
            {
                _logger.LogWarning("Snyk test {TestId} did not complete: {Errors}", test.Id, test.ErrorSummary);
                return new SnykTestRun { Test = test, Findings = [] };
            }

            var findings = await GetFindingsAsync(orgId, test.Id, cancellationToken);
            return new SnykTestRun { Test = test, Findings = findings };
        }
    }
}
