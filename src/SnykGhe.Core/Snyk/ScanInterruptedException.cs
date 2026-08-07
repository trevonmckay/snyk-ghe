namespace SnykGhe.Core.Snyk
{
    /// <summary>
    /// Thrown when a Snyk CLI child process is terminated by a signal (exit code ≥ 128) while the host is
    /// shutting down — the signature of a replica being scaled in or recycled mid-scan, not a scan that
    /// genuinely failed. Callers let it propagate so the queue transport abandons the delivery for
    /// redelivery, letting a healthy replica re-run the scan instead of reporting a false "could not complete".
    /// </summary>
    public sealed class ScanInterruptedException : Exception
    {
        public ScanInterruptedException(int exitCode)
            : base($"Snyk CLI terminated by signal (exit {exitCode}) during host shutdown; the delivery will be redelivered.")
        {
            ExitCode = exitCode;
        }

        /// <summary>The signal-derived exit code (128 + signal number) the CLI reported when it was killed.</summary>
        public int ExitCode { get; }
    }
}
