using System.Security.Cryptography;
using System.Text;

namespace SnykGhe.WebhookService.GitHub
{
    /// <summary>
    /// Validates the GitHub webhook <c>X-Hub-Signature-256</c> header (HMAC-SHA256 of the raw body).
    /// </summary>
    public static class GitHubWebhookSignatureValidator
    {
        private const string Prefix = "sha256=";

        public static bool IsValid(string secret, ReadOnlySpan<byte> body, string? signatureHeader)
        {
            if (string.IsNullOrEmpty(secret) ||
                string.IsNullOrEmpty(signatureHeader) ||
                !signatureHeader.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            Span<byte> hash = stackalloc byte[32];
            HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), body, hash);
            var computed = Convert.ToHexStringLower(hash);

            var provided = signatureHeader[Prefix.Length..];
            return CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(computed),
                Encoding.ASCII.GetBytes(provided));
        }
    }
}
