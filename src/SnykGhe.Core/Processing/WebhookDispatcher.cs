using System.Text;
using Microsoft.Extensions.Primitives;
using Octokit.Webhooks;
using SnykGhe.Contracts;

namespace SnykGhe.Core.Processing
{
    /// <summary>
    /// Routes a queued <see cref="GitHubWebhookMessage"/> to its handler. GitHub deliveries run through the
    /// Octokit event processor; internally queued baseline scans (see <see cref="BaselineScanMessage"/>) go
    /// straight to the baseline scanner. Every queue transport funnels through here so dispatch behaves
    /// identically. The signature was already validated at the front door, so this reconstructs only the
    /// headers the processor needs to route the event.
    /// </summary>
    public sealed class WebhookDispatcher
    {
        private readonly WebhookEventProcessor _processor;
        private readonly BaselineScanService _baselineScanService;

        public WebhookDispatcher(WebhookEventProcessor processor, BaselineScanService baselineScanService)
        {
            _processor = processor;
            _baselineScanService = baselineScanService;
        }

        public ValueTask DispatchAsync(GitHubWebhookMessage message)
        {
            if (string.Equals(message.EventName, BaselineScanMessage.EventName, StringComparison.Ordinal))
            {
                var request = BaselineScanMessage.Deserialize(message.Body);
                return request is null
                    ? ValueTask.CompletedTask
                    : new ValueTask(_baselineScanService.ProcessAsync(request, CancellationToken.None));
            }

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
