using SnykGhe.Core.Infrastructure;
using SnykGhe.Core.Snyk;

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
                catch (ScanInterruptedException ex)
                {
                    // In-process queue has no redelivery: the scan was killed by shutdown and cannot be
                    // retried here. Log it as an interrupted drain rather than a dispatch failure.
                    _logger.LogInformation(
                        "Draining: scan for delivery {Delivery} interrupted by shutdown ({Reason}); not retried (in-process queue).",
                        LogSanitizer.Clean(message.DeliveryId), ex.Message);
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
