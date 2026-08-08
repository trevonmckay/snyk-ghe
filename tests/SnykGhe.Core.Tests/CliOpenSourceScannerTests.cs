using SnykGhe.Core.Snyk;

namespace SnykGhe.Core.Tests
{
    public class CliOpenSourceScannerTests
    {
        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        public void InterpretOutcome_SuccessCodes_ParseOutput(int exitCode)
        {
            var outcome = new SnykCliOutcome { ExitCode = exitCode, StandardOutput = """{"ok":true,"vulnerabilities":[]}""" };

            var result = CliOpenSourceScanner.InterpretOutcome(outcome);

            Assert.False(result.Failed);
            Assert.False(result.NotApplicable);
            Assert.Single(result.Projects);
        }

        [Fact]
        public void InterpretOutcome_ExitCode3_IsNotApplicable_NotFailed()
        {
            // Exit 3 = no supported manifests. An infra-only repo has nothing for Open Source to scan; that is
            // a skipped check, not a "could not complete" failure.
            var outcome = new SnykCliOutcome { ExitCode = 3, StandardError = "Could not detect supported target files" };

            var result = CliOpenSourceScanner.InterpretOutcome(outcome);

            Assert.True(result.NotApplicable);
            Assert.False(result.Failed);
            Assert.Empty(result.Projects);
        }

        [Fact]
        public void InterpretOutcome_ExitCode2_Fails_WithStdErr()
        {
            var outcome = new SnykCliOutcome { ExitCode = 2, StandardError = "  bad usage  " };

            var result = CliOpenSourceScanner.InterpretOutcome(outcome);

            Assert.True(result.Failed);
            Assert.False(result.NotApplicable);
            Assert.Equal("bad usage", result.FailureMessage);
        }

        [Fact]
        public void InterpretOutcome_ExitCode2_NoStdErr_UsesGenericMessage()
        {
            var outcome = new SnykCliOutcome { ExitCode = 2, StandardError = "" };

            var result = CliOpenSourceScanner.InterpretOutcome(outcome);

            Assert.True(result.Failed);
            Assert.Equal("Snyk CLI exited with code 2.", result.FailureMessage);
        }

        [Fact]
        public void InterpretOutcome_UndocumentedExitCode_FallsThroughToFailure()
        {
            // The default arm guarantees an unexpected code is surfaced as a failure, never treated as a clean scan.
            var outcome = new SnykCliOutcome { ExitCode = 127 };

            var result = CliOpenSourceScanner.InterpretOutcome(outcome);

            Assert.True(result.Failed);
            Assert.False(result.NotApplicable);
            Assert.Equal("Snyk CLI exited with code 127.", result.FailureMessage);
        }

        [Fact]
        public void InterpretOutcome_AuthenticationFailed_Fails()
        {
            var result = CliOpenSourceScanner.InterpretOutcome(new SnykCliOutcome { AuthenticationFailed = true, ExitCode = 2 });

            Assert.True(result.Failed);
            Assert.Equal("Snyk OAuth authentication failed.", result.FailureMessage);
        }

        [Fact]
        public void InterpretOutcome_TimedOut_Fails()
        {
            var result = CliOpenSourceScanner.InterpretOutcome(new SnykCliOutcome { TimedOut = true, ExitCode = 2 });

            Assert.True(result.Failed);
            Assert.Equal("Snyk scan timed out.", result.FailureMessage);
        }
    }
}
