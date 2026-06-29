using System.Net;
using Azure.Messaging.ServiceBus;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SnykGhe.Contracts;

namespace SnykGhe.Functions
{
    /// <summary>
    /// HTTP front door for the scale-to-zero deployment topology. Validates the GitHub webhook signature
    /// and forwards the raw delivery to Service Bus, where a Container App consumes and scans. Keeping
    /// this tier thin lets the (slow, expensive) processing tier scale to zero while GitHub still gets a
    /// sub-second acknowledgement.
    /// </summary>
    public sealed class WebhookForwarder
    {
        private readonly ServiceBusSender _sender;
        private readonly FunctionOptions _options;
        private readonly ILogger<WebhookForwarder> _logger;

        public WebhookForwarder(ServiceBusSender sender, IOptions<FunctionOptions> options, ILogger<WebhookForwarder> logger)
        {
            _sender = sender;
            _options = options.Value;
            _logger = logger;
        }

        [Function("WebhookForwarder")]
        public async Task<HttpResponseData> Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "github/webhooks")] HttpRequestData request)
        {
            using var buffer = new MemoryStream();
            await request.Body.CopyToAsync(buffer);
            var bodyBytes = buffer.ToArray();

            var signature = GetHeader(request, "X-Hub-Signature-256");
            if (!GitHubWebhookSignatureValidator.IsValid(_options.WebhookSecret, bodyBytes, signature))
            {
                _logger.LogWarning("Rejected webhook delivery with invalid signature.");
                return request.CreateResponse(HttpStatusCode.Unauthorized);
            }

            var eventName = GetHeader(request, "X-GitHub-Event");
            if (string.IsNullOrEmpty(eventName))
            {
                return request.CreateResponse(HttpStatusCode.BadRequest);
            }

            // Carry the routing headers as Service Bus application properties (not in the body, which stays
            // the raw GitHub payload the consumer re-parses). Matches GitHubWebhookMessageProperties so the
            // Container App's ServiceBusWebhookWorker reads them back.
            var message = new ServiceBusMessage(BinaryData.FromBytes(bodyBytes))
            {
                ContentType = "application/json",
            };
            message.ApplicationProperties[GitHubWebhookMessageProperties.EventName] = eventName;

            var deliveryId = GetHeader(request, "X-GitHub-Delivery");
            if (!string.IsNullOrEmpty(deliveryId))
            {
                message.ApplicationProperties[GitHubWebhookMessageProperties.DeliveryId] = deliveryId;
                // GitHub redelivers with the same delivery id; surfacing it as the message id enables
                // Service Bus duplicate detection when the queue has it enabled.
                message.MessageId = deliveryId;
            }

            await _sender.SendMessageAsync(message);

            return request.CreateResponse(HttpStatusCode.OK);
        }

        private static string? GetHeader(HttpRequestData request, string name) =>
            request.Headers.TryGetValues(name, out var values) ? values.FirstOrDefault() : null;
    }
}
