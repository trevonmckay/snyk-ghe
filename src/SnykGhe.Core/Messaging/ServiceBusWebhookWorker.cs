using Azure.Messaging.ServiceBus;
using Microsoft.Extensions.Options;
using SnykGhe.Contracts;
using SnykGhe.Core.Configuration;
using SnykGhe.Core.Processing;

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

            // Let exceptions propagate: the processor abandons the message for redelivery / dead-lettering.
            await _dispatcher.DispatchAsync(message);
        }

        private Task OnErrorAsync(ProcessErrorEventArgs args)
        {
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
