using Amazon.SQS;
using Amazon.SQS.Model;
using Microsoft.Extensions.Options;
using SnykGhe.Contracts;
using SnykGhe.Core.Configuration;
using SnykGhe.Core.Processing;

namespace SnykGhe.Core.Messaging
{
    /// <summary>
    /// Durable webhook queue backed by Amazon SQS, the AWS counterpart to <see cref="ServiceBusWebhookQueue"/>.
    /// The raw webhook body is base64-encoded into the message body (SQS bodies are text) and the routing
    /// headers travel as message attributes, so the shared dispatcher runs unchanged on either cloud.
    /// Authentication uses the default AWS credential chain (the App Runner instance role).
    /// </summary>
    public sealed class SqsWebhookQueue : IWebhookQueue
    {
        private readonly IAmazonSQS _client;
        private readonly string _queueUrl;

        public SqsWebhookQueue(IAmazonSQS client, IOptions<SqsOptions> options)
        {
            _client = client;
            _queueUrl = options.Value.QueueUrl!;
        }

        public async ValueTask EnqueueAsync(GitHubWebhookMessage message, CancellationToken cancellationToken = default)
        {
            var request = new SendMessageRequest
            {
                QueueUrl = _queueUrl,
                MessageBody = Convert.ToBase64String(message.Body),
                MessageAttributes = new Dictionary<string, MessageAttributeValue>
                {
                    [GitHubWebhookMessageProperties.EventName] = new MessageAttributeValue
                    {
                        DataType = "String",
                        StringValue = message.EventName,
                    },
                },
            };

            if (!string.IsNullOrEmpty(message.DeliveryId))
            {
                request.MessageAttributes[GitHubWebhookMessageProperties.DeliveryId] = new MessageAttributeValue
                {
                    DataType = "String",
                    StringValue = message.DeliveryId,
                };
            }

            await _client.SendMessageAsync(request, cancellationToken);
        }
    }
}
