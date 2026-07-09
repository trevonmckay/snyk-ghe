using System.Net.Http.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SnykGhe.Core.Configuration;

namespace SnykGhe.Core.Snyk
{
    /// <summary>
    /// Exchanges a Snyk OAuth 2.0 client-credentials service account (<see cref="SnykOptions.OAuthClientId"/> +
    /// <see cref="SnykOptions.OAuthClientSecret"/>) for a short-lived access token via the RFC 6749
    /// client_credentials grant, and caches it until shortly before expiry. The Snyk CLI consumes the token
    /// through the <c>SNYK_OAUTH_TOKEN</c> environment variable — there is no env var for client id/secret, so
    /// the exchange has to happen here rather than being handed to the CLI directly.
    /// </summary>
    public sealed class SnykOAuthTokenProvider
    {
        // Refresh a minute early so an in-flight scan never starts with an about-to-expire token.
        private static readonly TimeSpan ExpirySkew = TimeSpan.FromSeconds(60);

        public const string HttpClientName = "snyk-oauth";

        private readonly IHttpClientFactory _httpClientFactory;
        private readonly SnykOptions _options;
        private readonly ILogger<SnykOAuthTokenProvider> _logger;
        private readonly SemaphoreSlim _gate;

        private string? _cachedToken;
        private DateTimeOffset _expiresAt;

        public SnykOAuthTokenProvider(IHttpClientFactory httpClientFactory, IOptions<SnykOptions> options, ILogger<SnykOAuthTokenProvider> logger)
        {
            _httpClientFactory = httpClientFactory;
            _options = options.Value;
            _logger = logger;
            _gate = new SemaphoreSlim(1, 1);
        }

        /// <summary>True when both OAuth client credentials are configured.</summary>
        public bool IsConfigured =>
            !string.IsNullOrWhiteSpace(_options.OAuthClientId) &&
            !string.IsNullOrWhiteSpace(_options.OAuthClientSecret);

        /// <summary>Returns a valid access token, exchanging or refreshing only when the cached one is stale.</summary>
        public async Task<string> GetAccessTokenAsync(CancellationToken cancellationToken = default)
        {
            if (TryGetCached(out var cached))
            {
                return cached;
            }

            await _gate.WaitAsync(cancellationToken);
            try
            {
                // Another caller may have refreshed while we waited on the gate.
                if (TryGetCached(out cached))
                {
                    return cached;
                }

                var token = await RequestTokenAsync(cancellationToken);
                _cachedToken = token.AccessToken;
                var lifetime = token.ExpiresIn > 0 ? TimeSpan.FromSeconds(token.ExpiresIn) : TimeSpan.FromHours(1);
                _expiresAt = DateTimeOffset.UtcNow + lifetime - ExpirySkew;
                return token.AccessToken;
            }
            finally
            {
                _gate.Release();
            }
        }

        private bool TryGetCached(out string token)
        {
            if (_cachedToken is not null && DateTimeOffset.UtcNow < _expiresAt)
            {
                token = _cachedToken;
                return true;
            }

            token = string.Empty;
            return false;
        }

        private async Task<TokenResponse> RequestTokenAsync(CancellationToken cancellationToken)
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, _options.OAuthTokenUrl);

            // Snyk's OAuth client uses the client_secret_post method (RFC 6749 §2.3.1): client_id and
            // client_secret go in the form body. It rejects client_secret_basic (Authorization header).
            request.Content = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("grant_type", "client_credentials"),
                new KeyValuePair<string, string>("client_id", _options.OAuthClientId ?? string.Empty),
                new KeyValuePair<string, string>("client_secret", _options.OAuthClientSecret ?? string.Empty),
            });

            var http = _httpClientFactory.CreateClient(HttpClientName);
            using var response = await http.SendAsync(request, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                var body = await response.Content.ReadAsStringAsync(cancellationToken);
                _logger.LogError("Snyk OAuth token exchange failed ({Status}): {Body}", (int)response.StatusCode, body.Trim());
                throw new InvalidOperationException($"Snyk OAuth token exchange failed with status {(int)response.StatusCode}.");
            }

            var token = await response.Content.ReadFromJsonAsync<TokenResponse>(cancellationToken);
            if (token is null || string.IsNullOrEmpty(token.AccessToken))
            {
                throw new InvalidOperationException("Snyk OAuth token exchange returned an empty access token.");
            }

            return token;
        }

        private sealed record TokenResponse
        {
            [JsonPropertyName("access_token")]
            public string AccessToken { get; init; } = string.Empty;

            [JsonPropertyName("token_type")]
            public string? TokenType { get; init; }

            [JsonPropertyName("expires_in")]
            public int ExpiresIn { get; init; }

            [JsonPropertyName("scope")]
            public string? Scope { get; init; }
        }
    }
}
