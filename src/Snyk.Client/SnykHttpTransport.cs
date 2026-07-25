using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace Snyk.Client
{
    /// <summary>
    /// HTTP plumbing shared by the resource APIs: bearer auth, the JSON:API media type, the mandatory
    /// <c>version</c> query parameter, cursor pagination, and error translation.
    /// </summary>
    internal sealed class SnykHttpTransport
    {
        /// <summary>The Snyk REST API is JSON:API; requests and responses use this media type.</summary>
        private const string JsonApiMediaType = "application/vnd.api+json";

        private readonly IHttpClientFactory _httpClientFactory;
        private readonly ISnykTokenProvider _tokenProvider;
        private readonly SnykApiOptions _options;
        private readonly ILogger _logger;

        internal SnykHttpTransport(
            IHttpClientFactory httpClientFactory,
            ISnykTokenProvider tokenProvider,
            SnykApiOptions options,
            ILogger logger)
        {
            _httpClientFactory = httpClientFactory;
            _tokenProvider = tokenProvider;
            _options = options;
            _logger = logger;
        }

        internal SnykApiOptions Options => _options;

        internal string ApiBase => _options.BaseUrl.TrimEnd('/');

        /// <summary>Builds an absolute REST URL with the required <c>version</c> parameter already applied.</summary>
        internal string BuildUrl(string path, params (string Key, string? Value)[] query)
        {
            var sb = new StringBuilder();
            sb.Append(ApiBase).Append("/rest").Append(path);
            sb.Append("?version=").Append(Uri.EscapeDataString(_options.ApiVersion));

            foreach (var (key, value) in query)
            {
                if (!string.IsNullOrWhiteSpace(value))
                {
                    sb.Append('&').Append(key).Append('=').Append(Uri.EscapeDataString(value));
                }
            }

            return sb.ToString();
        }

        internal async Task<JsonDocument> GetAsync(string url, CancellationToken cancellationToken)
        {
            using var response = await SendAsync(HttpMethod.Get, url, content: null, allowRedirect: true, cancellationToken);
            await EnsureSuccessAsync(response, url, cancellationToken);
            return await ReadJsonAsync(response, cancellationToken)
                ?? throw new SnykApiException($"Snyk returned an empty body for GET {url}.");
        }

        internal async Task<JsonDocument?> GetOrNullAsync(string url, CancellationToken cancellationToken)
        {
            using var response = await SendAsync(HttpMethod.Get, url, content: null, allowRedirect: true, cancellationToken);
            if (response.StatusCode == HttpStatusCode.NotFound)
            {
                return null;
            }

            await EnsureSuccessAsync(response, url, cancellationToken);
            return await ReadJsonAsync(response, cancellationToken);
        }

        internal async Task<JsonDocument> PostAsync(string url, string body, CancellationToken cancellationToken)
        {
            using var content = new StringContent(body, Encoding.UTF8);
            content.Headers.ContentType = new MediaTypeHeaderValue(JsonApiMediaType);

            using var response = await SendAsync(HttpMethod.Post, url, content, allowRedirect: true, cancellationToken);
            await EnsureSuccessAsync(response, url, cancellationToken);
            return await ReadJsonAsync(response, cancellationToken)
                ?? throw new SnykApiException($"Snyk returned an empty body for POST {url}.");
        }

        internal async Task<bool> DeleteAsync(string url, CancellationToken cancellationToken)
        {
            using var response = await SendAsync(HttpMethod.Delete, url, content: null, allowRedirect: true, cancellationToken);
            if (response.IsSuccessStatusCode)
            {
                return true;
            }

            var body = await SafeReadAsync(response, cancellationToken);
            _logger.LogWarning("Snyk DELETE {Url} failed ({Status}): {Body}", url, (int)response.StatusCode, body);
            return false;
        }

        /// <summary>
        /// Issues a GET without following redirects and returns the <c>Location</c> header, or null when the
        /// response was not a redirect. A completed test job answers with <c>303 See Other</c> pointing at the
        /// test resource, which is the only place the resulting test id is published.
        /// </summary>
        internal async Task<string?> GetRedirectLocationAsync(string url, CancellationToken cancellationToken)
        {
            using var response = await SendAsync(HttpMethod.Get, url, content: null, allowRedirect: false, cancellationToken);

            if (response.StatusCode is HttpStatusCode.SeeOther or HttpStatusCode.Found or HttpStatusCode.MovedPermanently)
            {
                return response.Headers.Location?.ToString();
            }

            if (!response.IsSuccessStatusCode)
            {
                await EnsureSuccessAsync(response, url, cancellationToken);
            }

            return null;
        }

        /// <summary>Walks a JSON:API collection, yielding each <c>data</c> element across every page.</summary>
        internal async Task<List<JsonElement>> GetPagedAsync(string url, CancellationToken cancellationToken)
        {
            var items = new List<JsonElement>();
            string? next = url;

            while (next is not null)
            {
                using var doc = await GetAsync(next, cancellationToken);
                var root = doc.RootElement;

                if (root.TryGetProperty("data", out var data) && data.ValueKind == JsonValueKind.Array)
                {
                    foreach (var item in data.EnumerateArray())
                    {
                        // The JsonDocument is disposed per page, so detach each element before it dies.
                        items.Add(item.Clone());
                    }
                }

                next = NextLink(root);
            }

            return items;
        }

        /// <summary>
        /// Resolves <c>links.next</c>, which Snyk emits as a root-relative path (occasionally as an object
        /// with an <c>href</c>). A missing or blank link terminates the walk.
        /// </summary>
        private string? NextLink(JsonElement root)
        {
            if (!root.TryGetProperty("links", out var links)
                || links.ValueKind != JsonValueKind.Object
                || !links.TryGetProperty("next", out var next))
            {
                return null;
            }

            var href = next.ValueKind switch
            {
                JsonValueKind.String => next.GetString(),
                JsonValueKind.Object when next.TryGetProperty("href", out var h) && h.ValueKind == JsonValueKind.String => h.GetString(),
                _ => null,
            };

            if (string.IsNullOrWhiteSpace(href))
            {
                return null;
            }

            if (href.StartsWith("http", StringComparison.OrdinalIgnoreCase))
            {
                return href;
            }

            return href.StartsWith('/') ? $"{ApiBase}{href}" : $"{ApiBase}/{href}";
        }

        private async Task<HttpResponseMessage> SendAsync(
            HttpMethod method,
            string url,
            HttpContent? content,
            bool allowRedirect,
            CancellationToken cancellationToken)
        {
            using var request = new HttpRequestMessage(method, url);
            var credential = await _tokenProvider.GetCredentialAsync(cancellationToken);
            request.Headers.Authorization = new AuthenticationHeaderValue(credential.Scheme, credential.Value);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(JsonApiMediaType));
            request.Content = content;

            // HttpClient follows redirects transparently; the test-job 303 must be observed, not followed.
            var clientName = allowRedirect ? SnykApiClient.HttpClientName : SnykApiClient.NoRedirectHttpClientName;
            var http = _httpClientFactory.CreateClient(clientName);
            return await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        }

        private static async Task<JsonDocument?> ReadJsonAsync(HttpResponseMessage response, CancellationToken cancellationToken)
        {
            var json = await response.Content.ReadAsStringAsync(cancellationToken);
            return string.IsNullOrWhiteSpace(json) ? null : JsonDocument.Parse(json);
        }

        private async Task EnsureSuccessAsync(HttpResponseMessage response, string url, CancellationToken cancellationToken)
        {
            if (response.IsSuccessStatusCode)
            {
                return;
            }

            var body = await SafeReadAsync(response, cancellationToken);
            var (detail, code) = ParseError(body);

            _logger.LogWarning("Snyk {Method} {Url} failed ({Status}): {Body}",
                response.RequestMessage?.Method, url, (int)response.StatusCode, body);

            throw new SnykApiException(
                detail ?? $"Snyk request to {url} failed with status {(int)response.StatusCode}.",
                (int)response.StatusCode,
                code);
        }

        private static async Task<string> SafeReadAsync(HttpResponseMessage response, CancellationToken cancellationToken)
        {
            try
            {
                return (await response.Content.ReadAsStringAsync(cancellationToken)).Trim();
            }
            catch (Exception)
            {
                return string.Empty;
            }
        }

        /// <summary>Pulls the first entry out of a JSON:API <c>errors</c> array, tolerating a non-JSON body.</summary>
        internal static (string? Detail, string? Code) ParseError(string body)
        {
            if (string.IsNullOrWhiteSpace(body))
            {
                return (null, null);
            }

            try
            {
                using var doc = JsonDocument.Parse(body);
                if (!doc.RootElement.TryGetProperty("errors", out var errors)
                    || errors.ValueKind != JsonValueKind.Array
                    || errors.GetArrayLength() == 0)
                {
                    return (null, null);
                }

                var first = errors[0];
                var detail = first.TryGetProperty("detail", out var d) && d.ValueKind == JsonValueKind.String
                    ? d.GetString()
                    : first.TryGetProperty("details", out var d2) && d2.ValueKind == JsonValueKind.String
                        ? d2.GetString()
                        : null;
                var code = first.TryGetProperty("code", out var c) && c.ValueKind == JsonValueKind.String
                    ? c.GetString()
                    : null;

                return (detail, string.IsNullOrWhiteSpace(code) ? null : code);
            }
            catch (JsonException)
            {
                return (null, null);
            }
        }
    }
}
