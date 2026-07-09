namespace SnykGhe.Contracts
{
    /// <summary>
    /// Service Bus application-property keys that carry the GitHub delivery headers alongside the raw
    /// webhook body. The producer (HTTP front door) and the consumer (scan processor) both reference
    /// these constants so the message contract is defined in exactly one place.
    /// </summary>
    public static class GitHubWebhookMessageProperties
    {
        /// <summary>Value of the GitHub <c>X-GitHub-Event</c> header; required to dispatch the event.</summary>
        public const string EventName = "X-GitHub-Event";

        /// <summary>Value of the GitHub <c>X-GitHub-Delivery</c> header; used for logging and dedup.</summary>
        public const string DeliveryId = "X-GitHub-Delivery";
    }
}
