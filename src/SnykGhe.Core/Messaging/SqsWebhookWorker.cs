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
                        // ApproximateReceiveCount drives the interrupted-scan redelivery backstop below.
                        MessageSystemAttributeNames = new List<string> { "ApproximateReceiveCount" },
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
            var receiveCount = ReceiveCount(sqsMessage);
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
            catch (ScanInterruptedException) when (
                ScanRedeliveryPolicy.ShouldRedeliver(receiveCount, _options.ScanInterruptionRedeliveryLimit))
            {
                // A scale-in/recycle killed the scan mid-run and it still has retry budget. Do not delete:
                // SQS redelivers after the visibility timeout so a healthy consumer re-runs it. Routine drain.
                _logger.LogInformation(
                    "Draining: scan for delivery {Delivery} interrupted by shutdown (receive {Count}); leaving for redelivery.",
                    LogSanitizer.Clean(deliveryId), receiveCount);
            }
            catch (ScanInterruptedException)
            {
                // Retry budget spent: delete so a scan that keeps getting scaled in does not loop to the DLQ.
                // The "could not complete" check already posted is the terminal state. A delete failure here
                // must not escape (it would fault the receive loop); on failure the message simply redelivers
                // and eventually dead-letters via redrive — the same bounded outcome, just less tidy.
                _logger.LogWarning(
                    "Scan for delivery {Delivery} interrupted by shutdown {Count} times (limit {Limit}); giving up, reported could-not-complete.",
                    LogSanitizer.Clean(deliveryId), receiveCount, _options.ScanInterruptionRedeliveryLimit);
                try
                {
                    await _client.DeleteMessageAsync(_options.QueueUrl, sqsMessage.ReceiptHandle, cancellationToken);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to delete given-up delivery {Delivery}; it will redeliver until redrive dead-letters it.",
                        LogSanitizer.Clean(deliveryId));
                }
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

        // SQS delivers ApproximateReceiveCount as a system attribute (1 on first receive, incrementing each
        // redelivery). Absent or unparseable, assume the first receive so an interrupted scan still retries.
        private static int ReceiveCount(Message message) =>
            message.Attributes is not null
            && message.Attributes.TryGetValue("ApproximateReceiveCount", out var raw)
            && int.TryParse(raw, out var count)
                ? count
                : 1;
    }
}
