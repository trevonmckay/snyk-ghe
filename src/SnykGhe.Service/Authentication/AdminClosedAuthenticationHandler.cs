using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace SnykGhe.Service.Authentication
{
    /// <summary>Options for the "closed" fallback scheme (no settings of its own).</summary>
    public sealed class AdminClosedAuthenticationOptions : AuthenticationSchemeOptions
    {
    }

    /// <summary>
    /// A scheme that never authenticates anyone. Registered as the only scheme on the <c>AdminAccess</c>
    /// policy when no auth method is enabled (empty <c>Auth:Methods</c>), so the admin API is simply closed
    /// — every request is rejected — while the app still starts and serves webhooks. Without it, an
    /// <c>[Authorize]</c> challenge with no registered scheme would surface a 500 instead of a clean 401.
    /// </summary>
    public sealed class AdminClosedAuthenticationHandler : AuthenticationHandler<AdminClosedAuthenticationOptions>
    {
        public const string SchemeName = "AdminClosed";

        public AdminClosedAuthenticationHandler(
            IOptionsMonitor<AdminClosedAuthenticationOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder)
            : base(options, logger, encoder)
        {
        }

        // Never authenticates; the base HandleChallengeAsync returns 401, which is the intended "closed" result.
        protected override Task<AuthenticateResult> HandleAuthenticateAsync() =>
            Task.FromResult(AuthenticateResult.NoResult());
    }
}
