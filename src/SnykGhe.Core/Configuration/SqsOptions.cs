namespace SnykGhe.Core.Configuration
{
    /// <summary>
    /// Durable webhook queue (Amazon SQS) configuration, the AWS counterpart to
    /// <see cref="ServiceBusOptions"/>. When <see cref="QueueUrl"/> is empty the service falls back to an
    /// in-process channel queue (local dev). Authentication uses the default AWS credential chain (the
    /// App Runner instance role); no access keys.
    /// </summary>
    public sealed class SqsOptions
    {
        public const string SectionName = "Sqs";

        /// <summary>Full SQS queue URL that carries raw, signature-validated webhook deliveries. Empty disables SQS.</summary>
        public string? QueueUrl { get; set; }

        /// <summary>AWS region. Falls back to the SDK's default resolution (AWS_REGION) when empty.</summary>
        public string? AwsRegion { get; set; }

        /// <summary>
        /// Messages received and processed per poll. Scans are heavy (clone + Snyk), so the default of 1
        /// keeps the worker sequential; raise it (up to the SQS batch maximum of 10) only if the instance
        /// has headroom for parallel scans.
        /// </summary>
        public int MaxConcurrentMessages { get; set; } = 1;

        /// <summary>
        /// Seconds a received message stays invisible to other consumers while a scan runs. It must exceed
        /// the longest expected clone + Snyk scan, otherwise SQS redelivers the message mid-scan and the
        /// work runs twice. Unlike Service Bus (5-minute lock cap), SQS honours this directly, up to its
        /// 12-hour maximum.
        /// </summary>
        public int VisibilityTimeoutSeconds { get; set; } = 1800;

        public bool IsConfigured => !string.IsNullOrWhiteSpace(QueueUrl);
    }
}
