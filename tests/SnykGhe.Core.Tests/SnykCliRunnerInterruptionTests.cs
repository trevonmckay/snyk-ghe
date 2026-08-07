using SnykGhe.Core.Snyk;

namespace SnykGhe.Core.Tests
{
    public class SnykCliRunnerInterruptionTests
    {
        [Theory]
        [InlineData(143)] // 128 + SIGTERM(15): a scaled-in / recycled replica
        [InlineData(137)] // 128 + SIGKILL(9): grace period elapsed, container hard-killed
        [InlineData(130)] // 128 + SIGINT(2)
        [InlineData(128)] // boundary: lowest signal-derived code
        public void IsShutdownInterruption_SignalKillWhileStopping_IsTrue(int exitCode)
        {
            Assert.True(SnykCliRunner.IsShutdownInterruption(exitCode, hostStopping: true));
        }

        [Theory]
        [InlineData(0)]   // clean
        [InlineData(1)]   // issues found (a successful scan)
        [InlineData(2)]   // CLI/usage error
        [InlineData(3)]   // no supported files
        [InlineData(127)] // command-not-found: below the signal range, a real failure
        public void IsShutdownInterruption_NonSignalExit_IsFalse_EvenWhileStopping(int exitCode)
        {
            Assert.False(SnykCliRunner.IsShutdownInterruption(exitCode, hostStopping: true));
        }

        [Theory]
        [InlineData(143)]
        [InlineData(137)]
        public void IsShutdownInterruption_SignalKillButNotStopping_IsFalse(int exitCode)
        {
            // A signal kill with the host NOT stopping (e.g. an OOM of the child) is a genuine,
            // non-retryable scan failure — it must report, not redeliver forever.
            Assert.False(SnykCliRunner.IsShutdownInterruption(exitCode, hostStopping: false));
        }

        [Fact]
        public void ScanInterruptedException_CarriesExitCode_AndDescribesRedelivery()
        {
            var ex = new ScanInterruptedException(143);

            Assert.Equal(143, ex.ExitCode);
            Assert.Contains("143", ex.Message);
            Assert.Contains("redeliver", ex.Message, StringComparison.OrdinalIgnoreCase);
        }
    }
}
