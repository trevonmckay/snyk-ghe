using Azure.Messaging.ServiceBus;
using Microsoft.Extensions.Options;
using SnykGhe.Contracts;
using SnykGhe.Core.Configuration;
using SnykGhe.Core.Infrastructure;
using SnykGhe.Core.Processing;
using SnykGhe.Core.Snyk;

namespace SnykGhe.Core.Messaging
{
    /// <summary>
    /// Consumes webhook deliveries from Azure Service Bus and dispatches them to the event processor.
    /// Messages auto-complete on success; a throwing handler abandons the message so Service Bus retries
    /// it and ultimately dead-letters it after the queue's max delivery count — giving at-least-once
    /// processing with no silent loss.
    /// </summary>
    public sealed class ServiceBusWebhookWorker : BackgroundService
    {
        private readonly ServiceBusClient _client;
        private readonly WebhookDispatcher _dispatcher;
        private readonly ServiceBusOptions _options;
        private readonly ILogger _logger;

        private ServiceBusProcessor? _processor;

        public ServiceBusWebhookWorker(
            ServiceBusClient client,
            WebhookDispatcher dispatcher,
            IOptions<ServiceBusOptions> options,
            ILogger<ServiceBusWebhookWorker> logger)
        {
            _client = client;
            _dispatcher = dispatcher;
            _options = options.Value;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _processor = _client.CreateProcessor(_options.QueueName, new ServiceBusProcessorOptions
            {
                AutoCompleteMessages = true,
                MaxConcurrentCalls = _options.MaxConcurrentCalls,
                MaxAutoLockRenewalDuration = TimeSpan.FromMinutes(_options.MaxAutoLockRenewalMinutes),
            });

            _processor.ProcessMessageAsync += OnMessageAsync;
            _processor.ProcessErrorAsync += OnErrorAsync;

            await _processor.StartProcessingAsync(stoppingToken);
        }

        private async Task OnMessageAsync(ProcessMessageEventArgs args)
        {
            var message = new GitHubWebhookMessage
            {
                Body = args.Message.Body.ToArray(),
                EventName = GetProperty(args.Message, GitHubWebhookMessageProperties.EventName) ?? string.Empty,
                DeliveryId = GetProperty(args.Message, GitHubWebhookMessageProperties.DeliveryId),
            };

            try
            {
                // Let exceptions propagate: the processor abandons the message for redelivery / dead-lettering.
                await _dispatcher.DispatchAsync(message);
            }
            catch (ScanInterruptedException ex)
            {
                // Expected during a scale-in/recycle: the scan was killed mid-run. Rethrow so the message is
                // abandoned and redelivered to a healthy replica, but log it as routine drain, not an error.
                _logger.LogInformation(
                    "Draining: scan for delivery {Delivery} interrupted by shutdown ({Reason}); abandoning for redelivery.",
                    LogSanitizer.Clean(message.DeliveryId), ex.Message);
                throw;
            }
        }

        private Task OnErrorAsync(ProcessErrorEventArgs args)
        {
            // A handler that threw ScanInterruptedException is surfaced here as a processing error; it is an
            // expected drain path (already logged at OnMessageAsync), so do not repeat it as an error.
            if (args.Exception is ScanInterruptedException)
            {
                return Task.CompletedTask;
            }

            _logger.LogError(args.Exception, "Service Bus webhook processor error from {Source}", args.ErrorSource);
            return Task.CompletedTask;
        }

        private static string? GetProperty(ServiceBusReceivedMessage message, string key) =>
            message.ApplicationProperties.TryGetValue(key, out var value) ? value?.ToString() : null;

        public override async Task StopAsync(CancellationToken cancellationToken)
        {
            if (_processor is not null)
            {
                await _processor.StopProcessingAsync(cancellationToken);
            }

            await base.StopAsync(cancellationToken);
        }

        public override void Dispose()
        {
            if (_processor is not null)
            {
                _processor.DisposeAsync().AsTask().GetAwaiter().GetResult();
            }

            base.Dispose();
        }
    }
}
