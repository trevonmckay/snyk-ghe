using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SnykGhe.Core.Configuration;
using SnykGhe.Service.Authentication;

namespace SnykGhe.Core.Tests
{
    public class AdminKeyAuthenticationHandlerTests
    {
        private const string AdminKey = "s3cret-admin-key";
        private const string RegisterPath = "/api/github/app/register";
        private const string AdminPath = "/api/admin/orgs/acme";

        private sealed class StaticOptionsMonitor<T> : IOptionsMonitor<T>
            where T : class
        {
            private readonly T _value;

            public StaticOptionsMonitor(T value)
            {
                _value = value;
            }

            public T CurrentValue => _value;
            public T Get(string? name) => _value;
            public IDisposable? OnChange(Action<T, string?> listener) => null;
        }

        private static async Task<AuthenticateResult> AuthenticateAsync(HttpContext context)
        {
            var handler = new AdminKeyAuthenticationHandler(
                new StaticOptionsMonitor<AdminKeyAuthenticationOptions>(new AdminKeyAuthenticationOptions()),
                NullLoggerFactory.Instance,
                UrlEncoder.Default,
                Options.Create(new AuthOptions { AdminKey = new AdminKeyOptions { Secret = AdminKey } }));

            var scheme = new AuthenticationScheme(
                AdminKeyAuthenticationHandler.SchemeName,
                AdminKeyAuthenticationHandler.SchemeName,
                typeof(AdminKeyAuthenticationHandler));

            await handler.InitializeAsync(scheme, context);
            return await handler.AuthenticateAsync();
        }

        private static HttpContext Context(string path)
        {
            var context = new DefaultHttpContext();
            context.Request.Path = path;
            return context;
        }

        [Fact]
        public async Task NoCredential_ReturnsNoResult_SoOtherSchemesCanTry()
        {
            var result = await AuthenticateAsync(Context(AdminPath));
            Assert.True(result.None);
            Assert.False(result.Succeeded);
        }

        [Fact]
        public async Task ValidHeaderKey_Succeeds_WithSchemeAsAuthenticationType()
        {
            var context = Context(AdminPath);
            context.Request.Headers[AdminKeyAuthenticationHandler.HeaderName] = AdminKey;

            var result = await AuthenticateAsync(context);

            Assert.True(result.Succeeded);
            Assert.Equal(AdminKeyAuthenticationHandler.SchemeName, result.Principal!.Identity!.AuthenticationType);
        }

        [Fact]
        public async Task WrongHeaderKey_Fails()
        {
            var context = Context(AdminPath);
            context.Request.Headers[AdminKeyAuthenticationHandler.HeaderName] = "not-the-key";

            var result = await AuthenticateAsync(context);

            Assert.False(result.Succeeded);
            Assert.NotNull(result.Failure);
        }

        [Fact]
        public async Task QueryKey_OnRegisterPath_Succeeds()
        {
            var context = Context(RegisterPath);
            context.Request.QueryString = new QueryString($"?key={AdminKey}");

            var result = await AuthenticateAsync(context);

            Assert.True(result.Succeeded);
        }

        [Fact]
        public async Task QueryKey_OnMutatingAdminPath_IsIgnored()
        {
            // A query-string secret is only honored on the browser-driven registration entry point; on the
            // mutating admin endpoints it must be ignored so keys never leak through access logs.
            var context = Context(AdminPath);
            context.Request.QueryString = new QueryString($"?key={AdminKey}");

            var result = await AuthenticateAsync(context);

            Assert.True(result.None);
        }

        [Fact]
        public async Task QueryKey_OnRegisterPath_WrongKey_Fails()
        {
            var context = Context(RegisterPath);
            context.Request.QueryString = new QueryString("?key=not-the-key");

            var result = await AuthenticateAsync(context);

            Assert.False(result.Succeeded);
            Assert.NotNull(result.Failure);
        }
    }
}
