using Azure.Messaging.ServiceBus;
using Microsoft.Extensions.Options;
using SnykGhe.Contracts;
using SnykGhe.Core.Configuration;
using SnykGhe.Core.Processing;

namespace SnykGhe.Core.Messaging
{
    /// <summary>
    /// Durable webhook queue backed by Azure Service Bus. Publishes the raw webhook body with the
    /// routing headers as application properties, so a consumer (this app or a separate processor
    /// Container App) can run the full event pipeline. Authentication is managed identity.
    /// </summary>
    public sealed class ServiceBusWebhookQueue : IWebhookQueue, IAsyncDisposable
    {
        private readonly ServiceBusSender _sender;

        public ServiceBusWebhookQueue(ServiceBusClient client, IOptions<ServiceBusOptions> options)
        {
            _sender = client.CreateSender(options.Value.QueueName);
        }

        public async ValueTask EnqueueAsync(GitHubWebhookMessage message, CancellationToken cancellationToken = default)
        {
            var sbMessage = new ServiceBusMessage(BinaryData.FromBytes(message.Body))
            {
                ContentType = "application/json",
            };

            sbMessage.ApplicationProperties[GitHubWebhookMessageProperties.EventName] = message.EventName;

            if (!string.IsNullOrEmpty(message.DeliveryId))
            {
                sbMessage.ApplicationProperties[GitHubWebhookMessageProperties.DeliveryId] = message.DeliveryId;
                // GitHub redelivers with the same delivery id; surfacing it as the message id enables
                // Service Bus duplicate detection when the queue has it enabled.
                sbMessage.MessageId = message.DeliveryId;
            }

            await _sender.SendMessageAsync(sbMessage, cancellationToken);
        }

        public ValueTask DisposeAsync() => _sender.DisposeAsync();
    }
}
