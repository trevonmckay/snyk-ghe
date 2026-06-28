using System.Threading.Channels;

namespace SnykGhe.Core.Processing
{
    /// <summary>
    /// In-process webhook queue backed by a bounded <see cref="Channel{T}"/>. Decouples the fast
    /// webhook ACK from slow scans without external infrastructure, but is NOT durable: anything still
    /// queued is lost on restart, crash, or scale-in. Use Service Bus in production; this is for local
    /// development and single-instance deployments.
    /// </summary>
    public sealed class ChannelWebhookQueue : IWebhookQueue
    {
        private readonly Channel<GitHubWebhookMessage> _channel = Channel.CreateBounded<GitHubWebhookMessage>(
            new BoundedChannelOptions(capacity: 100)
            {
                FullMode = BoundedChannelFullMode.Wait,
                SingleReader = true,
            });

        public async ValueTask EnqueueAsync(GitHubWebhookMessage message, CancellationToken cancellationToken = default)
        {
            await _channel.Writer.WriteAsync(message, cancellationToken);
        }

        public IAsyncEnumerable<GitHubWebhookMessage> ReadAllAsync(CancellationToken cancellationToken)
        {
            return _channel.Reader.ReadAllAsync(cancellationToken);
        }
    }
}
