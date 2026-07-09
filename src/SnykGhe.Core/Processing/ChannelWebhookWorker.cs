using SnykGhe.Core.Infrastructure;

namespace SnykGhe.Core.Processing
{
    /// <summary>Drains the in-process webhook queue and dispatches each delivery sequentially.</summary>
    public sealed class ChannelWebhookWorker : BackgroundService
    {
        private readonly ChannelWebhookQueue _queue;
        private readonly WebhookDispatcher _dispatcher;
        private readonly ILogger<ChannelWebhookWorker> _logger;

        public ChannelWebhookWorker(
            ChannelWebhookQueue queue,
            WebhookDispatcher dispatcher,
            ILogger<ChannelWebhookWorker> logger)
        {
            _queue = queue;
            _dispatcher = dispatcher;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            await foreach (var message in _queue.ReadAllAsync(stoppingToken))
            {
                try
                {
                    await _dispatcher.DispatchAsync(message);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to dispatch webhook delivery {Delivery}",
                        LogSanitizer.Clean(message.DeliveryId));
                }
            }
        }
    }
}
