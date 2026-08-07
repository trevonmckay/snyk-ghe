using Amazon.SQS;
using Amazon.SQS.Model;
using Microsoft.Extensions.Options;
using SnykGhe.Contracts;
using SnykGhe.Core.Configuration;
using SnykGhe.Core.Infrastructure;
using SnykGhe.Core.Processing;
using SnykGhe.Core.Snyk;

namespace SnykGhe.Core.Messaging
{
    /// <summary>
    /// Consumes webhook deliveries from Amazon SQS and dispatches them to the event processor, the AWS
    /// counterpart to <see cref="ServiceBusWebhookWorker"/>. A message is deleted only after it processes
    /// successfully; a failure (or crash) leaves it on the queue, so SQS redelivers it after the visibility
    /// timeout and ultimately moves it to the dead-letter queue once the redrive policy's maxReceiveCount
    /// is hit — at-least-once processing with no silent loss.
    /// </summary>
    public sealed class SqsWebhookWorker : BackgroundService
    {
        private const int LongPollSeconds = 20;
        private const int MaxSqsBatch = 10;

        private readonly IAmazonSQS _client;
        private readonly WebhookDispatcher _dispatcher;
        private readonly SqsOptions _options;
        private readonly ILogger _logger;

        public SqsWebhookWorker(
            IAmazonSQS client,
            WebhookDispatcher dispatcher,
            IOptions<SqsOptions> options,
            ILogger<SqsWebhookWorker> logger)
        {
            _client = client;
            _dispatcher = dispatcher;
            _options = options.Value;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            var batchSize = Math.Clamp(_options.MaxConcurrentMessages, 1, MaxSqsBatch);

            while (!stoppingToken.IsCancellationRequested)
            {
                ReceiveMessageResponse response;
                try
                {
                    response = await _client.ReceiveMessageAsync(new ReceiveMessageRequest
                    {
                        QueueUrl = _options.QueueUrl,
                        MaxNumberOfMessages = batchSize,
                        WaitTimeSeconds = LongPollSeconds,
                        VisibilityTimeout = _options.VisibilityTimeoutSeconds,
                        MessageAttributeNames = new List<string> { "All" },
                    }, stoppingToken);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error receiving from SQS; backing off before retry.");
                    await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);
                    continue;
                }

                if (response.Messages is not { Count: > 0 })
                {
                    continue;
                }

                await Task.WhenAll(response.Messages.Select(m => ProcessOneAsync(m, stoppingToken)));
            }
        }

        private async Task ProcessOneAsync(Message sqsMessage, CancellationToken cancellationToken)
        {
            var deliveryId = GetAttribute(sqsMessage, GitHubWebhookMessageProperties.DeliveryId);
            try
            {
                var message = new GitHubWebhookMessage
                {
                    Body = Convert.FromBase64String(sqsMessage.Body),
                    EventName = GetAttribute(sqsMessage, GitHubWebhookMessageProperties.EventName) ?? string.Empty,
                    DeliveryId = deliveryId,
                };

                await _dispatcher.DispatchAsync(message);

                await _client.DeleteMessageAsync(_options.QueueUrl, sqsMessage.ReceiptHandle, cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                // Shutting down: leave the message for redelivery after the visibility timeout.
            }
            catch (ScanInterruptedException ex)
            {
                // A scale-in/recycle killed the scan mid-run. Do not delete: SQS redelivers after the
                // visibility timeout so a healthy consumer re-runs it. Routine drain, not an error.
                _logger.LogInformation(
                    "Draining: scan for delivery {Delivery} interrupted by shutdown ({Reason}); leaving for redelivery.",
                    LogSanitizer.Clean(deliveryId), ex.Message);
            }
            catch (Exception ex)
            {
                // Do not delete: SQS redelivers after the visibility timeout, then dead-letters via redrive.
                _logger.LogError(ex, "Failed to dispatch webhook delivery {Delivery}", LogSanitizer.Clean(deliveryId));
            }
        }

        private static string? GetAttribute(Message message, string key) =>
            message.MessageAttributes is not null && message.MessageAttributes.TryGetValue(key, out var value)
                ? value.StringValue
                : null;
    }
}
