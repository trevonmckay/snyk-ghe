using System.Security.Cryptography;
using System.Text;

namespace SnykGhe.Contracts
{
    /// <summary>
    /// Validates the GitHub webhook <c>X-Hub-Signature-256</c> header (HMAC-SHA256 of the raw body).
    /// Lives in the shared contract assembly so the HTTP front door (Container App controller or Azure
    /// Function) and any other consumer validate signatures with identical, byte-for-byte logic.
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
