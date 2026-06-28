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
        private readonly FunctionOptions _options;
        private readonly ILogger<WebhookForwarder> _logger;

        public WebhookForwarder(IOptions<FunctionOptions> options, ILogger<WebhookForwarder> logger)
        {
            _options = options.Value;
            _logger = logger;
        }

        [Function("WebhookForwarder")]
        public async Task<ForwardResult> Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "github/webhooks")] HttpRequestData request)
        {
            using var buffer = new MemoryStream();
            await request.Body.CopyToAsync(buffer);
            var bodyBytes = buffer.ToArray();

            var signature = GetHeader(request, "X-Hub-Signature-256");
            if (!GitHubWebhookSignatureValidator.IsValid(_options.WebhookSecret, bodyBytes, signature))
            {
                _logger.LogWarning("Rejected webhook delivery with invalid signature.");
                return new ForwardResult { HttpResponse = request.CreateResponse(HttpStatusCode.Unauthorized) };
            }

            var eventName = GetHeader(request, "X-GitHub-Event");
            if (string.IsNullOrEmpty(eventName))
            {
                return new ForwardResult { HttpResponse = request.CreateResponse(HttpStatusCode.BadRequest) };
            }

            var message = new ServiceBusMessage(BinaryData.FromBytes(bodyBytes))
            {
                ContentType = "application/json",
            };
            message.ApplicationProperties[GitHubWebhookMessageProperties.EventName] = eventName;

            var deliveryId = GetHeader(request, "X-GitHub-Delivery");
            if (!string.IsNullOrEmpty(deliveryId))
            {
                message.ApplicationProperties[GitHubWebhookMessageProperties.DeliveryId] = deliveryId;
                message.MessageId = deliveryId;
            }

            return new ForwardResult
            {
                Message = message,
                HttpResponse = request.CreateResponse(HttpStatusCode.OK),
            };
        }

        private static string? GetHeader(HttpRequestData request, string name) =>
            request.Headers.TryGetValues(name, out var values) ? values.FirstOrDefault() : null;
    }

    /// <summary>
    /// Multi-output result: the Service Bus message (omitted when null, e.g. for rejected deliveries)
    /// plus the HTTP response returned to GitHub.
    /// </summary>
    public sealed class ForwardResult
    {
        [ServiceBusOutput("%ServiceBusQueueName%", Connection = "ServiceBusConnection")]
        public ServiceBusMessage? Message { get; set; }

        public HttpResponseData HttpResponse { get; set; } = default!;
    }
}
