using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using SnykGhe.Core.Configuration;
using SnykGhe.Core.Infrastructure;

namespace SnykGhe.Service.Authentication
{
    /// <summary>Options for the admin-key authentication scheme (no settings of its own).</summary>
    public sealed class AdminKeyAuthenticationOptions : AuthenticationSchemeOptions
    {
    }

    /// <summary>
    /// Authenticates the legacy shared admin key. The key arrives in the <c>X-Admin-Key</c> header, and
    /// additionally as a <c>?key=</c> query parameter <em>only</em> on the browser-driven registration entry
    /// point — a query-string secret is logged by proxies and lands in browser history, so it is never
    /// accepted on the mutating admin endpoints. Comparison is constant-time via <see cref="AdminApiKeyGuard"/>.
    /// A request with no key produces <see cref="AuthenticateResult.NoResult"/> so another enabled scheme
    /// (OAuth2) can still authenticate it.
    /// </summary>
    public sealed class AdminKeyAuthenticationHandler : AuthenticationHandler<AdminKeyAuthenticationOptions>
    {
        public const string SchemeName = "AdminKey";
        public const string HeaderName = "X-Admin-Key";

        // Browser navigation cannot set request headers, so the registration page (a GET opened in a
        // browser) is the one place the key may travel in the query string.
        private const string QueryKeyAllowedPath = "/api/github/app/register";

        private readonly AdminKeyOptions _adminKey;

        public AdminKeyAuthenticationHandler(
            IOptionsMonitor<AdminKeyAuthenticationOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            IOptions<AuthOptions> auth)
            : base(options, logger, encoder)
        {
            _adminKey = auth.Value.AdminKey;
        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var provided = Request.Headers[HeaderName].FirstOrDefault();

            if (provided is null && Request.Path.Equals(QueryKeyAllowedPath, StringComparison.OrdinalIgnoreCase))
            {
                provided = Request.Query["key"].FirstOrDefault();
            }

            if (provided is null)
            {
                return Task.FromResult(AuthenticateResult.NoResult());
            }

            if (!AdminApiKeyGuard.Matches(provided, _adminKey.Secret))
            {
                return Task.FromResult(AuthenticateResult.Fail("Invalid admin key."));
            }

            var identity = new ClaimsIdentity(
                [new Claim(ClaimTypes.Name, "admin-key")],
                SchemeName);
            var ticket = new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName);
            return Task.FromResult(AuthenticateResult.Success(ticket));
        }
    }
}
