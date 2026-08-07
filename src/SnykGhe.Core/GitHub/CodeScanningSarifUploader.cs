using System.Collections.Concurrent;
using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SnykGhe.Core.Configuration;

namespace SnykGhe.Core.GitHub
{
    /// <summary>
    /// Best-effort upload of a Snyk Code SARIF report to GitHub code scanning, so findings surface in the
    /// repository's Security tab with GitHub-rendered source snippets (GitHub supplies the source that the
    /// Snyk Web UI cannot show for a CLI-origin scan). Octokit 14 has no code-scanning client, so this calls
    /// the REST endpoint directly with the installation token.
    ///
    /// Every failure is swallowed — code scanning is an additive surface and the gating Check Run has already
    /// reported. A repo without GitHub Advanced Security, or an App without <c>security_events: write</c>,
    /// answers 403/404; that is expected and cached so a full SARIF is not re-uploaded to it on every PR.
    /// 400/413 mean a malformed or oversized payload on our side and are logged at warning.
    ///
    /// Concrete by design (like <c>SnykApiClient</c>): tests substitute the <see cref="HttpMessageHandler"/>
    /// behind the named <see cref="HttpClient"/> to assert request shape and response handling.
    /// </summary>
    public sealed class CodeScanningSarifUploader
    {
        public const string HttpClientName = "github-code-scanning";

        // GitHub's pinned REST API version. The SARIF upload endpoint is stable across versions; pin it so a
        // server-side default shift cannot change the contract.
        private const string ApiVersion = "2022-11-28";

        // Repos that answered 403/404 are skipped until this elapses, so a large SARIF is not POSTed every PR
        // to a repo that structurally cannot accept it (no GHAS / no permission).
        private static readonly TimeSpan UnavailableTtl = TimeSpan.FromHours(6);

        private readonly IHttpClientFactory _httpClientFactory;
        private readonly GitHubOptions _options;
        private readonly ILogger<CodeScanningSarifUploader> _logger;
        private readonly ConcurrentDictionary<string, DateTimeOffset> _unavailableUntil =
            new(StringComparer.OrdinalIgnoreCase);

        public CodeScanningSarifUploader(
            IHttpClientFactory httpClientFactory,
            IOptions<GitHubOptions> options,
            ILogger<CodeScanningSarifUploader>? logger = null)
        {
            _httpClientFactory = httpClientFactory;
            _options = options.Value;
            _logger = logger ?? NullLogger<CodeScanningSarifUploader>.Instance;
        }

        /// <summary>
        /// Uploads a Code SARIF for a pull request head commit. Never throws for an upload failure; only a
        /// cancellation propagates. The <paramref name="sarif"/> is sent verbatim (GitHub honors the SARIF
        /// <c>suppressions</c> field, so Snyk's Web UI ignores carry over as dismissed alerts).
        /// </summary>
        public async Task UploadAsync(
            string owner,
            string repo,
            string commitSha,
            int prNumber,
            string sarif,
            string installationToken,
            CancellationToken cancellationToken)
        {
            var repoKey = $"{owner}/{repo}";

            if (string.IsNullOrWhiteSpace(_options.ApiBaseUrl))
            {
                _logger.LogWarning("GitHub:ApiBaseUrl is not configured; skipping SARIF upload for {Repo}.", repoKey);
                return;
            }

            if (IsKnownUnavailable(repoKey))
            {
                _logger.LogDebug("Skipping SARIF upload for {Repo}: code scanning known unavailable.", repoKey);
                return;
            }

            try
            {
                var client = _httpClientFactory.CreateClient(HttpClientName);
                using var httpRequest = BuildRequest(owner, repo, commitSha, prNumber, sarif, installationToken);
                using var response = await client.SendAsync(httpRequest, cancellationToken);
                await HandleResponseAsync(response, repoKey, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                // Network/transient error — never fail the scan over the additive upload.
                _logger.LogWarning(ex, "SARIF upload to code scanning failed for {Repo}.", repoKey);
            }
        }

        private HttpRequestMessage BuildRequest(
            string owner, string repo, string commitSha, int prNumber, string sarif, string installationToken)
        {
            // ApiBaseUrl is documented to carry a trailing slash; trim defensively so the path never doubles it.
            var url = $"{_options.ApiBaseUrl!.TrimEnd('/')}/repos/{owner}/{repo}/code-scanning/sarifs";

            var payload = new SarifUploadPayload
            {
                CommitSha = commitSha,
                // Attach the analysis to the PR head so alerts surface on the pull request.
                Ref = $"refs/pull/{prNumber}/head",
                Sarif = GzipBase64(sarif),
            };

            var request = new HttpRequestMessage(HttpMethod.Post, url)
            {
                Content = JsonContent.Create(payload),
            };
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", installationToken);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
            request.Headers.TryAddWithoutValidation("X-GitHub-Api-Version", ApiVersion);
            request.Headers.UserAgent.ParseAdd(_options.ProductName);
            return request;
        }

        private async Task HandleResponseAsync(HttpResponseMessage response, string repoKey, CancellationToken cancellationToken)
        {
            if (response.StatusCode == HttpStatusCode.Accepted)
            {
                var id = await ReadSarifIdAsync(response, cancellationToken);
                _logger.LogInformation(
                    "Uploaded Snyk Code SARIF to code scanning for {Repo} (sarif id {Id}).", repoKey, id ?? "(unknown)");
                return;
            }

            var detail = await SafeBodyAsync(response, cancellationToken);
            switch ((int)response.StatusCode)
            {
                case 403 or 404:
                    // GHAS not enabled, repo archived, or the App lacks security_events:write — structural, so
                    // stop re-uploading to this repo for a while.
                    MarkUnavailable(repoKey);
                    _logger.LogInformation(
                        "Code scanning unavailable for {Repo} (HTTP {Status}); skipping SARIF upload for {Hours}h. {Detail}",
                        repoKey, (int)response.StatusCode, UnavailableTtl.TotalHours, detail);
                    break;
                case 400 or 413:
                    // Malformed SARIF or payload over GitHub's size limit — our side; surface loudly.
                    _logger.LogWarning(
                        "GitHub rejected the Snyk Code SARIF for {Repo} (HTTP {Status}): {Detail}",
                        repoKey, (int)response.StatusCode, detail);
                    break;
                default:
                    _logger.LogWarning(
                        "Unexpected response uploading SARIF for {Repo} (HTTP {Status}): {Detail}",
                        repoKey, (int)response.StatusCode, detail);
                    break;
            }
        }

        private static async Task<string?> ReadSarifIdAsync(HttpResponseMessage response, CancellationToken cancellationToken)
        {
            try
            {
                await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
                using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
                return doc.RootElement.TryGetProperty("id", out var id) ? id.ToString() : null;
            }
            catch (Exception)
            {
                return null;
            }
        }

        private static async Task<string> SafeBodyAsync(HttpResponseMessage response, CancellationToken cancellationToken)
        {
            try
            {
                var body = await response.Content.ReadAsStringAsync(cancellationToken);
                return body.Length > 500 ? body[..500] : body;
            }
            catch (Exception)
            {
                return string.Empty;
            }
        }

        private static string GzipBase64(string sarif)
        {
            var bytes = Encoding.UTF8.GetBytes(sarif);
            using var output = new MemoryStream();
            using (var gzip = new GZipStream(output, CompressionLevel.Optimal, leaveOpen: true))
            {
                gzip.Write(bytes, 0, bytes.Length);
            }

            return Convert.ToBase64String(output.ToArray());
        }

        private bool IsKnownUnavailable(string repoKey) =>
            _unavailableUntil.TryGetValue(repoKey, out var until) && until > DateTimeOffset.UtcNow;

        private void MarkUnavailable(string repoKey) =>
            _unavailableUntil[repoKey] = DateTimeOffset.UtcNow + UnavailableTtl;

        private sealed class SarifUploadPayload
        {
            [JsonPropertyName("commit_sha")] public required string CommitSha { get; init; }

            [JsonPropertyName("ref")] public required string Ref { get; init; }

            [JsonPropertyName("sarif")] public required string Sarif { get; init; }
        }
    }
}
