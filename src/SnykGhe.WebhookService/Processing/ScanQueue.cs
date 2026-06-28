using System.Threading.Channels;

namespace SnykGhe.WebhookService.Processing
{
    /// <summary>
    /// In-process work queue decoupling fast webhook ACK from slow Snyk scans. GitHub requires a
    /// webhook response within ~10s, so the receiver enqueues and the background worker scans.
    /// Graduate to Azure Storage Queue / Service Bus when durability or scale-out is needed.
    /// </summary>
    public interface IScanQueue
    {
        ValueTask EnqueueAsync(ScanRequest request, CancellationToken cancellationToken = default);
        IAsyncEnumerable<ScanRequest> DequeueAllAsync(CancellationToken cancellationToken);
    }

    public sealed class ChannelScanQueue : IScanQueue
    {
        private readonly Channel<ScanRequest> _channel = Channel.CreateBounded<ScanRequest>(
            new BoundedChannelOptions(capacity: 100)
            {
                FullMode = BoundedChannelFullMode.Wait,
                SingleReader = true,
            });

        public ValueTask EnqueueAsync(ScanRequest request, CancellationToken cancellationToken = default) =>
            _channel.Writer.WriteAsync(request, cancellationToken);

        public IAsyncEnumerable<ScanRequest> DequeueAllAsync(CancellationToken cancellationToken) =>
            _channel.Reader.ReadAllAsync(cancellationToken);
    }
}
