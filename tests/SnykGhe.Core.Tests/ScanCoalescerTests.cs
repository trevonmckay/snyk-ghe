using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SnykGhe.Core.Configuration;
using SnykGhe.Core.Processing;
using SnykGhe.Core.Storage;

namespace SnykGhe.Core.Tests
{
    public class ScanCoalescerTests
    {
        /// <summary>
        /// Programmable coordination store: <see cref="AcquireResult"/> drives the claim, <see cref="CompleteResults"/>
        /// is dequeued per pass (each value is the "next sha to scan", null ends the loop and — as the real store
        /// does — releases the lease), and the throw flags exercise the fail-open paths. Records call counts.
        /// </summary>
        private sealed class FakeStore : IScanCoordinationStore
        {
            public ScanClaim AcquireResult { get; set; } = ScanClaim.Acquired;
            public bool ThrowOnAcquire { get; set; }
            public bool ThrowOnComplete { get; set; }
            public Queue<string?> CompleteResults { get; } = new();

            public int AcquireCount { get; private set; }
            public int CompleteCount { get; private set; }
            public int ReleaseCount { get; private set; }

            public Task EnsureCreatedAsync(CancellationToken cancellationToken) => Task.CompletedTask;

            public Task<ScanClaim> TryAcquireAsync(string key, string requestedSha, string leaseToken, TimeSpan lease, CancellationToken cancellationToken)
            {
                AcquireCount++;
                if (ThrowOnAcquire)
                {
                    throw new InvalidOperationException("store down");
                }

                return Task.FromResult(AcquireResult);
            }

            public Task<string?> CompletePassAsync(string key, string leaseToken, string requestedSha, string scannedSha, TimeSpan lease, CancellationToken cancellationToken)
            {
                CompleteCount++;
                if (ThrowOnComplete)
                {
                    throw new InvalidOperationException("store down");
                }

                return Task.FromResult(CompleteResults.Count > 0 ? CompleteResults.Dequeue() : null);
            }

            public Task ReleaseAsync(string key, string leaseToken, CancellationToken cancellationToken)
            {
                ReleaseCount++;
                return Task.CompletedTask;
            }
        }

        private static ScanCoalescer Build(FakeStore store, bool coalesce = true) => new(
            store,
            Options.Create(new SnykOptions { CoalesceBaselineScans = coalesce, ScanLeaseMinutes = 30 }),
            NullLogger<ScanCoalescer>.Instance);

        private static Func<CancellationToken, Task<string>> Counting(Action onScan) =>
            _ => { onScan(); return Task.FromResult("scanned-tip"); };

        [Fact]
        public async Task Acquired_with_no_new_push_scans_once_and_completes_pass()
        {
            var store = new FakeStore(); // Acquired, empty CompleteResults → CompletePass returns null (releases)
            var coalescer = Build(store);
            var scans = 0;

            await coalescer.RunAsync("acme/widget#main", "sha1", Counting(() => scans++), CancellationToken.None);

            Assert.Equal(1, scans);
            Assert.Equal(1, store.AcquireCount);
            Assert.Equal(1, store.CompleteCount);
            Assert.Equal(0, store.ReleaseCount); // CompletePassAsync released the lease; no separate release
        }

        [Fact]
        public async Task Coalesced_skips_the_scan_entirely()
        {
            var store = new FakeStore { AcquireResult = ScanClaim.Coalesced };
            var coalescer = Build(store);
            var scans = 0;

            await coalescer.RunAsync("acme/widget#main", "sha1", Counting(() => scans++), CancellationToken.None);

            Assert.Equal(0, scans); // folded into the in-flight scan
            Assert.Equal(1, store.AcquireCount);
            Assert.Equal(0, store.CompleteCount);
            Assert.Equal(0, store.ReleaseCount);
        }

        [Fact]
        public async Task Already_scanned_skips_the_scan_entirely()
        {
            var store = new FakeStore { AcquireResult = ScanClaim.AlreadyScanned };
            var coalescer = Build(store);
            var scans = 0;

            await coalescer.RunAsync("acme/widget#main", "sha1", Counting(() => scans++), CancellationToken.None);

            Assert.Equal(0, scans); // redelivery or a commit already covered by a prior scan
            Assert.Equal(0, store.CompleteCount);
            Assert.Equal(0, store.ReleaseCount);
        }

        [Fact]
        public async Task Newer_commit_during_scan_triggers_one_more_pass()
        {
            var store = new FakeStore();
            store.CompleteResults.Enqueue("sha2"); // a push arrived during the first scan
            store.CompleteResults.Enqueue(null);   // nothing new during the second scan
            var coalescer = Build(store);
            var scans = 0;

            await coalescer.RunAsync("acme/widget#main", "sha1", Counting(() => scans++), CancellationToken.None);

            Assert.Equal(2, scans); // many rapid pushes still collapse to two passes
            Assert.Equal(2, store.CompleteCount);
            Assert.Equal(0, store.ReleaseCount);
        }

        [Fact]
        public async Task Acquire_failure_falls_open_to_a_direct_scan()
        {
            var store = new FakeStore { ThrowOnAcquire = true };
            var coalescer = Build(store);
            var scans = 0;

            await coalescer.RunAsync("acme/widget#main", "sha1", Counting(() => scans++), CancellationToken.None);

            Assert.Equal(1, scans); // storage hiccup must not skip the scan
            Assert.Equal(0, store.CompleteCount);
            Assert.Equal(0, store.ReleaseCount);
        }

        [Fact]
        public async Task Completion_failure_ends_the_run_and_releases_as_a_safety_net()
        {
            var store = new FakeStore { ThrowOnComplete = true };
            var coalescer = Build(store);
            var scans = 0;

            await coalescer.RunAsync("acme/widget#main", "sha1", Counting(() => scans++), CancellationToken.None);

            Assert.Equal(1, scans);
            Assert.Equal(1, store.ReleaseCount); // lease released despite the completion error
        }

        [Fact]
        public async Task Scan_exception_releases_the_lease_and_propagates()
        {
            var store = new FakeStore();
            var coalescer = Build(store);

            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                coalescer.RunAsync("acme/widget#main", "sha1",
                    _ => throw new InvalidOperationException("scan blew up"), CancellationToken.None));

            Assert.Equal(1, store.ReleaseCount);
        }

        [Fact]
        public async Task Coalescing_disabled_scans_directly_without_touching_the_store()
        {
            var store = new FakeStore();
            var coalescer = Build(store, coalesce: false);
            var scans = 0;

            await coalescer.RunAsync("acme/widget#main", "sha1", Counting(() => scans++), CancellationToken.None);

            Assert.Equal(1, scans);
            Assert.Equal(0, store.AcquireCount);
            Assert.Equal(0, store.ReleaseCount);
        }
    }
}
