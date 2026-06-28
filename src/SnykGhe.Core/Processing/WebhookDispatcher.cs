using System.Text;
using Microsoft.Extensions.Primitives;
using Octokit.Webhooks;
using SnykGhe.Contracts;

namespace SnykGhe.Core.Processing
{
    /// <summary>
    /// Runs a queued <see cref="GitHubWebhookMessage"/> through the event processor. Both the in-process and
    /// Service Bus workers funnel through here so dispatch behaves identically across queue transports.
    /// The signature was already validated at the front door, so this reconstructs only the headers the
    /// processor needs to route the event.
    /// </summary>
    public sealed class WebhookDispatcher
    {
        private readonly WebhookEventProcessor _processor;

        public WebhookDispatcher(WebhookEventProcessor processor)
        {
            _processor = processor;
        }

        public ValueTask DispatchAsync(GitHubWebhookMessage message)
        {
            var headers = new Dictionary<string, StringValues>
            {
                [GitHubWebhookMessageProperties.EventName] = message.EventName,
            };

            if (!string.IsNullOrEmpty(message.DeliveryId))
            {
                headers[GitHubWebhookMessageProperties.DeliveryId] = message.DeliveryId;
            }

            var body = Encoding.UTF8.GetString(message.Body);
            return _processor.ProcessWebhookAsync(headers, body);
        }
    }
}
