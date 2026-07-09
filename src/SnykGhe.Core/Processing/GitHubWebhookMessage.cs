namespace SnykGhe.Core.Processing
{
    /// <summary>
    /// A signature-validated GitHub webhook delivery waiting to be dispatched. Carrying the raw body
    /// plus the routing headers (rather than a parsed scan request) keeps the queue payload tiny and
    /// lets one consumer run the full event-processing pipeline regardless of the front door.
    /// </summary>
    public sealed record GitHubWebhookMessage
    {
        /// <summary>Raw request body bytes exactly as delivered by GitHub.</summary>
        public required byte[] Body { get; init; }

        /// <summary>Value of the <c>X-GitHub-Event</c> header (e.g. <c>pull_request</c>).</summary>
        public required string EventName { get; init; }

        /// <summary>Value of the <c>X-GitHub-Delivery</c> header, if present.</summary>
        public string? DeliveryId { get; init; }
    }
}
