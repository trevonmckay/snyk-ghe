using Microsoft.Extensions.Logging.Abstractions;
using SnykGhe.Core.Snyk;

namespace SnykGhe.Core.Tests
{
    public class SnykCliRetryTests
    {
        private static readonly SnykCliOutcome Clean = new() { ExitCode = 0 };

        private static readonly SnykCliOutcome BackendError = new()
        {
            ExitCode = 2,
            StandardOutput = "{\"ok\": false, \"error\": \"one or more components failed to be processed\"}",
        };

        private static Func<CancellationToken, Task<SnykCliOutcome>> Sequence(List<SnykCliOutcome> outcomes, Counter counter) =>
            _ =>
            {
                var outcome = outcomes[Math.Min(counter.Value, outcomes.Count - 1)];
                counter.Value++;
                return Task.FromResult(outcome);
            };

        private static Task<SnykCliOutcome> RetryAsync(
            List<SnykCliOutcome> outcomes,
            Counter counter,
            int maxRetries,
            CancellationToken cancellationToken = default) =>
            SnykCliRunner.RetryAsync(
                Sequence(outcomes, counter),
                SnykCliRunner.IsTransientFailure,
                maxRetries,
                TimeSpan.Zero,
                TimeSpan.FromMinutes(5),
                TimeProvider.System,
                NullLogger.Instance,
                cancellationToken);

        [Fact]
        public async Task RetryAsync_FirstAttemptSucceeds_RunsOnce()
        {
            var counter = new Counter();

            var outcome = await RetryAsync([Clean], counter, maxRetries: 1);

            Assert.Same(Clean, outcome);
            Assert.Equal(1, counter.Value);
        }

        [Fact]
        public async Task RetryAsync_TransientFailureThenSuccess_ReturnsTheRetryOutcome()
        {
            var counter = new Counter();

            var outcome = await RetryAsync([BackendError, Clean], counter, maxRetries: 1);

            Assert.Same(Clean, outcome);
            Assert.Equal(2, counter.Value);
        }

        [Theory]
        [InlineData(1)]
        [InlineData(3)]
        public async Task RetryAsync_PersistentTransientFailure_StopsAtMaxRetriesAndReturnsTheFailure(int maxRetries)
        {
            var counter = new Counter();

            var outcome = await RetryAsync([BackendError], counter, maxRetries);

            Assert.Same(BackendError, outcome);
            Assert.Equal(maxRetries + 1, counter.Value);
        }

        [Fact]
        public async Task RetryAsync_ZeroMaxRetries_RunsOnce()
        {
            var counter = new Counter();

            var outcome = await RetryAsync([BackendError, Clean], counter, maxRetries: 0);

            Assert.Same(BackendError, outcome);
            Assert.Equal(1, counter.Value);
        }

        [Fact]
        public async Task RetryAsync_NonRetryableFailure_RunsOnce()
        {
            var counter = new Counter();
            var timedOut = new SnykCliOutcome { TimedOut = true };

            var outcome = await RetryAsync([timedOut, Clean], counter, maxRetries: 1);

            Assert.Same(timedOut, outcome);
            Assert.Equal(1, counter.Value);
        }

        [Fact]
        public async Task RetryAsync_CancelledBeforeRetry_Throws()
        {
            var counter = new Counter();
            using var cts = new CancellationTokenSource();
            Func<CancellationToken, Task<SnykCliOutcome>> attempt = _ =>
            {
                counter.Value++;
                cts.Cancel();
                return Task.FromResult(BackendError);
            };

            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => SnykCliRunner.RetryAsync(
                attempt, SnykCliRunner.IsTransientFailure, 1, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(5),
                TimeProvider.System, NullLogger.Instance, cts.Token));
            Assert.Equal(1, counter.Value);
        }

        [Theory]
        [InlineData(301, 1)] // failed after more than the limit: not retried
        [InlineData(300, 2)] // failed exactly at the limit: retried
        public async Task RetryAsync_SlowFailedAttempt_IsNotRetried(int attemptSeconds, int expectedAttempts)
        {
            var clock = new ManualTimeProvider();
            var counter = new Counter();
            Func<CancellationToken, Task<SnykCliOutcome>> attempt = _ =>
            {
                counter.Value++;
                clock.Advance(TimeSpan.FromSeconds(attemptSeconds));
                return Task.FromResult(BackendError);
            };

            var outcome = await SnykCliRunner.RetryAsync(
                attempt, SnykCliRunner.IsTransientFailure, 1, TimeSpan.Zero, TimeSpan.FromSeconds(300),
                clock, NullLogger.Instance, CancellationToken.None);

            Assert.Same(BackendError, outcome);
            Assert.Equal(expectedAttempts, counter.Value);
        }

        [Fact]
        public async Task RetryAsync_SlowRetry_EndsFurtherRetries()
        {
            var clock = new ManualTimeProvider();
            var counter = new Counter();
            Func<CancellationToken, Task<SnykCliOutcome>> attempt = _ =>
            {
                counter.Value++;
                clock.Advance(TimeSpan.FromSeconds(counter.Value == 1 ? 10 : 400));
                return Task.FromResult(BackendError);
            };

            await SnykCliRunner.RetryAsync(
                attempt, SnykCliRunner.IsTransientFailure, 3, TimeSpan.Zero, TimeSpan.FromSeconds(300),
                clock, NullLogger.Instance, CancellationToken.None);

            Assert.Equal(2, counter.Value);
        }

        [Theory]
        [InlineData(0, false)]   // no issues
        [InlineData(1, false)]   // issues found — a successful scan
        [InlineData(2, true)]    // CLI / Snyk backend error
        [InlineData(3, false)]   // no supported files
        [InlineData(137, false)] // signal kill outside host shutdown (e.g. OOM of the child)
        public void IsTransientFailure_ClassifiesByExitCode(int exitCode, bool expected)
        {
            Assert.Equal(expected, SnykCliRunner.IsTransientFailure(new SnykCliOutcome { ExitCode = exitCode }));
        }

        [Fact]
        public void IsTransientFailure_TimeoutOrAuthFailure_IsFalse()
        {
            Assert.False(SnykCliRunner.IsTransientFailure(new SnykCliOutcome { ExitCode = 2, TimedOut = true }));
            Assert.False(SnykCliRunner.IsTransientFailure(new SnykCliOutcome { ExitCode = 2, AuthenticationFailed = true }));
        }

        [Fact]
        public void ProductIsRetryable_BackendError_IsTrue()
        {
            Assert.True(CliProductScanRunner.IsRetryable(BackendError));
        }

        [Theory]
        [InlineData("Snyk Code is not enabled for this org")]
        [InlineData("Could not find any valid IaC files")]
        [InlineData("Failed to parse JSON file")]
        public void ProductIsRetryable_NotApplicableExit2_IsFalse(string stderr)
        {
            Assert.False(CliProductScanRunner.IsRetryable(new SnykCliOutcome { ExitCode = 2, StandardError = stderr }));
        }

        private sealed class Counter
        {
            public int Value { get; set; }
        }

        private sealed class ManualTimeProvider : TimeProvider
        {
            private long _timestamp;

            public override long TimestampFrequency => TimeSpan.TicksPerSecond;

            public override long GetTimestamp() => _timestamp;

            public void Advance(TimeSpan by) => _timestamp += by.Ticks;
        }
    }
}
