using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using SnykGhe.Contracts;
using SnykGhe.Core.Configuration;
using SnykGhe.Core.Infrastructure;
using SnykGhe.Core.Processing;

namespace SnykGhe.Service.Controllers
{
    /// <summary>
    /// Receives GitHub App webhook deliveries, validates the signature, and enqueues the raw delivery
    /// for background processing so the request returns well within GitHub's ~10s timeout. One endpoint
    /// serves every installed org.
    /// </summary>
    [ApiController]
    [Route("api/github/webhooks")]
    public sealed class WebhooksController : ControllerBase
    {
        private readonly IWebhookQueue _queue;
        private readonly GitHubOptions _options;
        private readonly ILogger<WebhooksController> _logger;

        public WebhooksController(
            IWebhookQueue queue,
            IOptions<GitHubOptions> options,
            ILogger<WebhooksController> logger)
        {
            _queue = queue;
            _options = options.Value;
            _logger = logger;
        }

        [HttpPost]
        public async Task<IActionResult> Receive()
        {
            using var buffer = new MemoryStream();
            await Request.Body.CopyToAsync(buffer, HttpContext.RequestAborted);
            var bodyBytes = buffer.ToArray();

            var signature = Request.Headers["X-Hub-Signature-256"].FirstOrDefault();
            if (!GitHubWebhookSignatureValidator.IsValid(_options.WebhookSecret, bodyBytes, signature))
            {
                // Sanitize the attacker-controlled delivery header before logging (prevents log forging).
                var deliveryId = LogSanitizer.Clean(Request.Headers["X-GitHub-Delivery"].FirstOrDefault());
                _logger.LogWarning("Rejected webhook delivery {Delivery} with invalid signature.", deliveryId);
                return Unauthorized();
            }

            var eventName = Request.Headers["X-GitHub-Event"].FirstOrDefault();
            if (string.IsNullOrEmpty(eventName))
            {
                return BadRequest();
            }

            var message = new GitHubWebhookMessage
            {
                Body = bodyBytes,
                EventName = eventName,
                DeliveryId = Request.Headers["X-GitHub-Delivery"].FirstOrDefault(),
            };

            await _queue.EnqueueAsync(message, HttpContext.RequestAborted);
            return Ok();
        }
    }
}
