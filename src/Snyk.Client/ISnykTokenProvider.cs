namespace Snyk.Client
{
    /// <summary>
    /// A credential for the Snyk REST API. Snyk accepts two authorization schemes and they are not
    /// interchangeable: a service-account API key must be sent as <c>Token &lt;key&gt;</c>, while an OAuth
    /// access token must be sent as <c>Bearer &lt;token&gt;</c>.
    /// </summary>
    public sealed class SnykCredential
    {
        /// <summary>The HTTP authorization scheme: <c>Token</c> or <c>Bearer</c>.</summary>
        public required string Scheme { get; init; }

        public required string Value { get; init; }

        public static SnykCredential ApiToken(string token) => new() { Scheme = "Token", Value = token };

        public static SnykCredential Bearer(string accessToken) => new() { Scheme = "Bearer", Value = accessToken };
    }

    /// <summary>
    /// Supplies the credential for Snyk REST calls. The client does not know how it was obtained (static
    /// service-account key, OAuth client-credentials exchange, refreshed session), so a host can plug in
    /// whichever scheme it uses. Implementations must be safe for concurrent use and are expected to cache
    /// and refresh internally.
    /// </summary>
    public interface ISnykTokenProvider
    {
        ValueTask<SnykCredential> GetCredentialAsync(CancellationToken cancellationToken = default);
    }
}
