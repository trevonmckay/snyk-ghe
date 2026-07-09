using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using SnykGhe.Core.Configuration;
using SnykGhe.Core.GitHub.Manifest;
using SnykGhe.Core.Secrets;
using SnykGhe.Core.Storage;

namespace SnykGhe.Service.Controllers
{
    /// <summary>
    /// Self-service GitHub App registration via the manifest flow. <c>/register</c> (admin-gated) renders a
    /// form that pre-fills an App on the GitHub host; GitHub redirects back to <c>/created</c> with a
    /// one-time code, which is exchanged for the App's credentials and written to the secret store.
    /// </summary>
    [ApiController]
    public sealed class AppRegistrationController : ControllerBase
    {
        private static readonly TimeSpan StateMaxAge = TimeSpan.FromHours(1);

        private static readonly JsonSerializerOptions ManifestJson = new()
        {
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        };

        private readonly GitHubAppManifestService _manifest;
        private readonly RegistrationStateProtector _state;
        private readonly IAppCredentialStore _credentialStore;
        private readonly IAppConfigStore _appConfig;
        private readonly RegistrationOptions _registration;
        private readonly StorageOptions _storage;
        private readonly ILogger<AppRegistrationController> _logger;

        public AppRegistrationController(
            GitHubAppManifestService manifest,
            RegistrationStateProtector state,
            IAppCredentialStore credentialStore,
            IAppConfigStore appConfig,
            IOptions<RegistrationOptions> registration,
            IOptions<StorageOptions> storage,
            ILogger<AppRegistrationController> logger)
        {
            _manifest = manifest;
            _state = state;
            _credentialStore = credentialStore;
            _appConfig = appConfig;
            _registration = registration.Value;
            _storage = storage.Value;
            _logger = logger;
        }

        [HttpGet("api/github/app/register")]
        public IActionResult Register([FromQuery] string? org)
        {
            if (!_state.IsEnabled || !IsAuthorized())
            {
                return Unauthorized();
            }

            try
            {
                var state = _state.Issue();
                var manifest = _manifest.BuildManifest(_registration.AppName, ResolvePublicBaseUrl(), _registration.WebhookUrl);
                var target = _manifest.NewAppUrl(org, state);
                var json = JsonSerializer.Serialize(manifest, ManifestJson);
                return Content(RenderRegisterPage(target, json), "text/html; charset=utf-8");
            }
            catch (InvalidOperationException ex)
            {
                return Problem(ex.Message);
            }
        }

        [HttpGet("api/github/app/created")]
        public async Task<IActionResult> Created(
            [FromQuery] string? code,
            [FromQuery] string? state,
            CancellationToken cancellationToken)
        {
            if (!_state.Validate(state, StateMaxAge))
            {
                return Unauthorized();
            }

            if (string.IsNullOrWhiteSpace(code))
            {
                return BadRequest("Missing manifest code.");
            }

            ManifestConversionResponse conversion;
            try
            {
                conversion = await _manifest.ConvertCodeAsync(code, cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "GitHub App manifest conversion failed.");
                return Problem(
                    "Manifest conversion failed; the code may have expired (valid one hour). " +
                    "Restart at /api/github/app/register.");
            }

            var credentials = new AppCredentials
            {
                AppId = conversion.Id.ToString(),
                PrivateKeyPem = conversion.Pem!,
                WebhookSecret = conversion.WebhookSecret,
                ClientId = conversion.ClientId,
                ClientSecret = conversion.ClientSecret,
            };

            await _credentialStore.WriteAsync(credentials, cancellationToken);
            await _appConfig.SetAppIdAsync(credentials.AppId, cancellationToken);
            _logger.LogInformation(
                "Registered GitHub App {AppId} ({Slug}); secrets written to {Store}, App ID saved to storage",
                conversion.Id, conversion.Slug, _credentialStore.Describe());

            return Content(RenderCreatedPage(conversion, credentials), "text/html; charset=utf-8");
        }

        private string ResolvePublicBaseUrl() =>
            string.IsNullOrWhiteSpace(_registration.PublicBaseUrl)
                ? $"{Request.Scheme}://{Request.Host}"
                : _registration.PublicBaseUrl.TrimEnd('/');

        private bool IsAuthorized()
        {
            if (string.IsNullOrEmpty(_storage.AdminApiKey))
            {
                return false;
            }

            var provided = Request.Headers["X-Admin-Key"].FirstOrDefault()
                ?? Request.Query["key"].FirstOrDefault();

            return provided is not null && CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(provided),
                Encoding.UTF8.GetBytes(_storage.AdminApiKey));
        }

        private static string RenderRegisterPage(Uri target, string manifestJson)
        {
            var action = HtmlEncoder.Default.Encode(target.ToString());
            var manifest = HtmlEncoder.Default.Encode(manifestJson);
            return $$"""
                <!doctype html>
                <html><head><meta charset="utf-8"><title>Create GitHub App</title></head>
                <body>
                  <p>Redirecting to GitHub to create the App…</p>
                  <form id="f" method="post" action="{{action}}">
                    <input type="hidden" name="manifest" value="{{manifest}}">
                    <button type="submit">Continue to GitHub</button>
                  </form>
                  <script>document.getElementById('f').submit();</script>
                </body></html>
                """;
        }

        private string RenderCreatedPage(ManifestConversionResponse conversion, AppCredentials credentials)
        {
            var appId = HtmlEncoder.Default.Encode(credentials.AppId);
            var slug = HtmlEncoder.Default.Encode(conversion.Slug ?? "the app");
            var htmlUrl = conversion.HtmlUrl is null ? "#" : HtmlEncoder.Default.Encode(conversion.HtmlUrl);
            var store = HtmlEncoder.Default.Encode(_credentialStore.Describe());

            var secretsBlock = _credentialStore.PersistsSecrets
                ? $"<p>The private key and webhook secret were written to <strong>{store}</strong>, and the App ID ({appId}) was saved to storage. Restart the service so it loads the new secrets, then install the App on your orgs.</p>"
                : $"""
                    <p><strong>No secret store is configured</strong> — copy these now; they are shown only once:</p>
                    <p>App ID: <code>{appId}</code></p>
                    <p>Webhook secret: <code>{HtmlEncoder.Default.Encode(credentials.WebhookSecret ?? string.Empty)}</code></p>
                    <p>Private key (PEM):</p>
                    <pre>{HtmlEncoder.Default.Encode(credentials.PrivateKeyPem)}</pre>
                    """;

            return $$"""
                <!doctype html>
                <html><head><meta charset="utf-8"><title>GitHub App created</title></head>
                <body>
                  <h1>GitHub App created</h1>
                  <p>App <a href="{{htmlUrl}}">{{slug}}</a> (ID {{appId}}) is registered.</p>
                  {{secretsBlock}}
                </body></html>
                """;
        }
    }
}
