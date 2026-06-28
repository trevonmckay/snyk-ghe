using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Octokit.Webhooks;
using SnykGhe.WebhookService.Configuration;
using SnykGhe.WebhookService.GitHub;
using SnykGhe.WebhookService.Infrastructure;

namespace SnykGhe.WebhookService.Controllers
{
    /// <summary>
    /// Receives GitHub App webhook deliveries, validates the signature, and dispatches to the
    /// registered <see cref="WebhookEventProcessor"/>. One endpoint serves every installed org.
    /// </summary>
    [ApiController]
    [Route("api/github/webhooks")]
    public sealed class WebhooksController : ControllerBase
    {
        private readonly WebhookEventProcessor _processor;
        private readonly GitHubOptions _options;
        private readonly ILogger<WebhooksController> _logger;

        public WebhooksController(
            WebhookEventProcessor processor,
            IOptions<GitHubOptions> options,
            ILogger<WebhooksController> logger)
        {
            _processor = processor;
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

            var body = Encoding.UTF8.GetString(bodyBytes);
            await _processor.ProcessWebhookAsync(Request.Headers, body);
            return Ok();
        }
    }
}
