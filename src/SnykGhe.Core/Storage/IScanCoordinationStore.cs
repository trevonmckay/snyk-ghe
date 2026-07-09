namespace SnykGhe.Core.Storage
{
    /// <summary>Outcome of trying to claim a baseline-scan slot for a branch.</summary>
    public enum ScanClaim
    {
        /// <summary>This caller holds the single-flight lease and should scan.</summary>
        Acquired,

        /// <summary>Another live holder exists; the requested commit was recorded for it to pick up. Do not scan.</summary>
        Coalesced,

        /// <summary>The requested commit has already been scanned (redelivery or a superseded push). Do not scan.</summary>
        AlreadyScanned,
    }

    /// <summary>
    /// Durable, cross-replica coordination for baseline scans so a burst of pushes to one branch collapses to
    /// a single in-flight scan (latest commit wins) instead of one scan per push, and an already-scanned commit
    /// (Service Bus redelivery, or a push the in-flight scan's clone already picked up) is not re-scanned.
    /// Keyed by <c>{owner}/{repo}#{branch}</c>. Backed by Azure Table or DynamoDB (mirrors the installation registry).
    /// </summary>
    public interface IScanCoordinationStore
    {
        Task EnsureCreatedAsync(CancellationToken cancellationToken);

        /// <summary>
        /// Records <paramref name="requestedSha"/> as the latest commit wanted for <paramref name="key"/> and
        /// decides whether this caller should scan:
        /// <list type="bullet">
        /// <item><see cref="ScanClaim.AlreadyScanned"/> when the requested commit equals the last successfully
        /// scanned commit.</item>
        /// <item><see cref="ScanClaim.Acquired"/> when the single-flight lease was free/expired and is now held
        /// by this caller.</item>
        /// <item><see cref="ScanClaim.Coalesced"/> when a live holder already exists.</item>
        /// </list>
        /// </summary>
        Task<ScanClaim> TryAcquireAsync(string key, string requestedSha, string leaseToken, TimeSpan lease, CancellationToken cancellationToken);

        /// <summary>
        /// Called by the lease holder after a successful scan pass. Records <paramref name="scannedSha"/> (the
        /// commit actually cloned and scanned) as the last-scanned commit, then atomically decides what happens
        /// next: if a newer commit was requested during the scan (the recorded request differs from
        /// <paramref name="requestedSha"/>), renews the lease and returns the new commit to scan next; otherwise
        /// releases the lease and returns <c>null</c>. Releasing here (rather than in a separate step) closes the
        /// race where a push arriving between the "nothing new" check and the release would be dropped.
        /// </summary>
        Task<string?> CompletePassAsync(string key, string leaseToken, string requestedSha, string scannedSha, TimeSpan lease, CancellationToken cancellationToken);

        /// <summary>
        /// Releases the lease if it is still held by <paramref name="leaseToken"/>; a no-op otherwise. Used as a
        /// safety net when a scan throws before <see cref="CompletePassAsync"/> runs.
        /// </summary>
        Task ReleaseAsync(string key, string leaseToken, CancellationToken cancellationToken);
    }
}
