namespace SnykGhe.Core.Processing
{
    /// <summary>
    /// Producer seam for the webhook queue. The HTTP controller enqueues here after validating the
    /// signature; a background worker drains the queue and dispatches each delivery. Implementations
    /// are an in-process channel (local dev) or Azure Service Bus (durable, scalable).
    /// </summary>
    public interface IWebhookQueue
    {
        ValueTask EnqueueAsync(GitHubWebhookMessage message, CancellationToken cancellationToken = default);
    }
}
