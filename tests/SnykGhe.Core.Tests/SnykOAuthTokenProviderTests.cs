using System.Net;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SnykGhe.Core.Configuration;
using SnykGhe.Core.Snyk;

namespace SnykGhe.Core.Tests
{
    public class SnykOAuthTokenProviderTests
    {
        private sealed class CapturingHandler : HttpMessageHandler
        {
            private readonly string _responseJson;

            public CapturingHandler(string responseJson)
            {
                _responseJson = responseJson;
            }

            public int Calls { get; private set; }
            public HttpRequestMessage? LastRequest { get; private set; }
            public string? LastBody { get; private set; }

            protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                Calls++;
                LastRequest = request;
                LastBody = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(_responseJson, Encoding.UTF8, "application/json"),
                };
            }
        }

        private sealed class StubHttpClientFactory : IHttpClientFactory
        {
            private readonly HttpMessageHandler _handler;

            public StubHttpClientFactory(HttpMessageHandler handler)
            {
                _handler = handler;
            }

            public HttpClient CreateClient(string name) => new(_handler, disposeHandler: false);
        }

        private static SnykOAuthTokenProvider Build(HttpMessageHandler handler, SnykOptions options) => new(
            new StubHttpClientFactory(handler),
            Options.Create(options),
            NullLogger<SnykOAuthTokenProvider>.Instance);

        [Fact]
        public void IsConfigured_RequiresBothCredentials()
        {
            var handler = new CapturingHandler("{}");
            Assert.False(Build(handler, new SnykOptions { OAuthClientId = "id" }).IsConfigured);
            Assert.False(Build(handler, new SnykOptions { OAuthClientSecret = "secret" }).IsConfigured);
            Assert.True(Build(handler, new SnykOptions { OAuthClientId = "id", OAuthClientSecret = "secret" }).IsConfigured);
        }

        [Fact]
        public async Task GetAccessTokenAsync_ExchangesCredentialsWithClientCredentialsGrant()
        {
            var handler = new CapturingHandler("""{"access_token":"tok-123","token_type":"bearer","expires_in":3600}""");
            var provider = Build(handler, new SnykOptions
            {
                OAuthClientId = "client-id",
                OAuthClientSecret = "client-secret",
                OAuthTokenUrl = "https://api.snyk.io/oauth2/token",
            });

            var token = await provider.GetAccessTokenAsync();

            Assert.Equal("tok-123", token);
            Assert.Equal(HttpMethod.Post, handler.LastRequest!.Method);
            Assert.Equal("https://api.snyk.io/oauth2/token", handler.LastRequest.RequestUri!.ToString());
            // Snyk requires client_secret_post: credentials in the body, not an Authorization header.
            Assert.Null(handler.LastRequest.Headers.Authorization);
            Assert.Contains("grant_type=client_credentials", handler.LastBody);
            Assert.Contains("client_id=client-id", handler.LastBody);
            Assert.Contains("client_secret=client-secret", handler.LastBody);
        }

        [Fact]
        public async Task GetAccessTokenAsync_CachesTokenUntilExpiry()
        {
            var handler = new CapturingHandler("""{"access_token":"tok-123","expires_in":3600}""");
            var provider = Build(handler, new SnykOptions
            {
                OAuthClientId = "client-id",
                OAuthClientSecret = "client-secret",
            });

            await provider.GetAccessTokenAsync();
            await provider.GetAccessTokenAsync();

            Assert.Equal(1, handler.Calls);
        }
    }
}
