using Microsoft.Extensions.Options;
using SnykGhe.Core.Configuration;
using SnykGhe.Core.Storage;

namespace SnykGhe.Core.Processing
{
    /// <summary>
    /// Runs a baseline scan under a durable single-flight lease so a burst of pushes to one branch collapses
    /// to a single in-flight scan (latest commit wins) and two workers never scan the same branch at once.
    /// The lease holder re-scans once per commit generation that arrives during a scan, then releases.
    ///
    /// Fail-open: coordination is an optimization, not a correctness requirement, so any coordination-store
    /// error falls back to running the scan directly rather than skipping it.
    /// </summary>
    public sealed class ScanCoalescer
    {
        private readonly IScanCoordinationStore _store;
        private readonly SnykOptions _options;
        private readonly ILogger _logger;

        public ScanCoalescer(
            IScanCoordinationStore store,
            IOptions<SnykOptions> options,
            ILogger<ScanCoalescer> logger)
        {
            _store = store;
            _options = options.Value;
            _logger = logger;
        }

        /// <summary>
        /// Runs <paramref name="scan"/> for <paramref name="key"/> at most once per commit generation, honoring
        /// the single-flight lease and skipping an already-scanned commit. <paramref name="scan"/> returns the
        /// commit SHA it actually cloned and scanned. When coalescing is disabled, runs <paramref name="scan"/> directly.
        /// </summary>
        public async Task RunAsync(string key, string requestedSha, Func<CancellationToken, Task<string>> scan, CancellationToken cancellationToken)
        {
            if (!_options.CoalesceBaselineScans)
            {
                await scan(cancellationToken);
                return;
            }

            var lease = TimeSpan.FromMinutes(_options.ScanLeaseMinutes);
            var leaseToken = Guid.NewGuid().ToString("N");

            ScanClaim claim;
            try
            {
                claim = await _store.TryAcquireAsync(key, requestedSha, leaseToken, lease, cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Scan coordination unavailable for {Key}; scanning without coalescing.", key);
                await scan(cancellationToken);
                return;
            }

            switch (claim)
            {
                case ScanClaim.AlreadyScanned:
                    _logger.LogInformation("Baseline scan for {Key} skipped; commit {Sha} was already scanned.", key, requestedSha);
                    return;
                case ScanClaim.Coalesced:
                    _logger.LogInformation("Baseline scan for {Key} coalesced into an in-flight scan.", key);
                    return;
            }

            var passSha = requestedSha;
            var released = false;
            try
            {
                while (true)
                {
                    var scannedSha = await scan(cancellationToken);

                    string? next;
                    try
                    {
                        next = await _store.CompletePassAsync(key, leaseToken, passSha, scannedSha, lease, cancellationToken);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Scan coordination completion failed for {Key}; ending run after this pass.", key);
                        break;
                    }

                    if (next is null)
                    {
                        released = true; // CompletePassAsync released the lease atomically
                        break;
                    }

                    passSha = next;
                    _logger.LogInformation("Baseline scan for {Key} re-running for a newer commit.", key);
                }
            }
            finally
            {
                if (!released)
                {
                    try
                    {
                        await _store.ReleaseAsync(key, leaseToken, cancellationToken);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Failed to release scan lease for {Key}; it will expire on its own.", key);
                    }
                }
            }
        }
    }
}
