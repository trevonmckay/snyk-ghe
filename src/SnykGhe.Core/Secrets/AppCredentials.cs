namespace SnykGhe.Core.Secrets
{
    /// <summary>GitHub App credentials produced by the manifest-conversion step.</summary>
    public sealed record AppCredentials
    {
        public required string AppId { get; init; }

        public required string PrivateKeyPem { get; init; }

        public string? WebhookSecret { get; init; }

        public string? ClientId { get; init; }

        public string? ClientSecret { get; init; }
    }
}
