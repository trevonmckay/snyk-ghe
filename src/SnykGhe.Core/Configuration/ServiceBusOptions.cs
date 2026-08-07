namespace SnykGhe.Core.Configuration
{
    /// <summary>
    /// Durable webhook queue (Azure Service Bus) configuration. When <see cref="FullyQualifiedNamespace"/>
    /// is empty the service falls back to an in-process channel queue, which is convenient for local
    /// development but loses queued work on restart. Authentication is always managed identity
    /// (<c>DefaultAzureCredential</c>); no connection strings.
    /// </summary>
    public sealed class ServiceBusOptions
    {
        public const string SectionName = "ServiceBus";

        /// <summary>e.g. <c>my-namespace.servicebus.windows.net</c>. Empty disables Service Bus.</summary>
        public string? FullyQualifiedNamespace { get; set; }

        /// <summary>Queue that carries raw, signature-validated webhook deliveries.</summary>
        public string QueueName { get; set; } = "webhook-deliveries";

        /// <summary>
        /// Messages processed concurrently per replica. Scans are heavy (clone + Snyk), so the default
        /// of 1 keeps each replica sequential and lets KEDA add replicas for throughput instead.
        /// </summary>
        public int MaxConcurrentCalls { get; set; } = 1;

        /// <summary>
        /// Upper bound on how long the processor keeps renewing a message lock while a scan runs. It must
        /// exceed the longest expected clone + Snyk scan, otherwise the lock expires mid-scan and the
        /// delivery is processed again. Service Bus caps a single lock at 5 minutes, so this renewal
        /// window is what actually covers long scans.
        /// </summary>
        public int MaxAutoLockRenewalMinutes { get; set; } = 30;

        /// <summary>
        /// How many times a scan killed by host shutdown (a scaled-in / recycled replica) is redelivered
        /// before the worker stops retrying and lets the posted "could not complete" check stand. Compared
        /// against the delivery count, so with the default of 3 the scan is attempted on deliveries 1–3 and
        /// given up on the 4th. Keep it below the queue's max delivery count (5) so an interruption that keeps
        /// recurring settles with a reported check instead of silently dead-lettering, and never loops forever.
        /// </summary>
        public int ScanInterruptionRedeliveryLimit { get; set; } = 3;

        public bool IsConfigured => !string.IsNullOrWhiteSpace(FullyQualifiedNamespace);
    }
}
