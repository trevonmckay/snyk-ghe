namespace SnykGhe.Core.Snyk
{
    /// <summary>
    /// Thrown when no Snyk credentials are configured at all. This is a permanent misconfiguration, not a
    /// transient fault, so callers that retry on failure (e.g. the queue-driven cleanup) can catch this
    /// specifically and give up rather than redelivering forever. It derives from
    /// <see cref="InvalidOperationException"/> so existing broad handlers keep their behaviour, while a
    /// <em>failed</em> token exchange (which stays a plain <see cref="InvalidOperationException"/>) remains
    /// retryable.
    /// </summary>
    public sealed class SnykCredentialsNotConfiguredException : InvalidOperationException
    {
        public SnykCredentialsNotConfiguredException(string message)
            : base(message)
        {
        }
    }
}
