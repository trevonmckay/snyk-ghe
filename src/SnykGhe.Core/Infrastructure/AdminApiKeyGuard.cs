using System.Security.Cryptography;
using System.Text;

namespace SnykGhe.Core.Infrastructure
{
    /// <summary>
    /// Constant-time comparison for the admin API key that guards the mapping and manual-scan endpoints.
    /// Closed by default: a missing configured key or a missing provided key never authorizes.
    /// </summary>
    public static class AdminApiKeyGuard
    {
        public static bool Matches(string? provided, string? configured)
        {
            if (string.IsNullOrEmpty(configured) || provided is null)
            {
                return false;
            }

            // FixedTimeEquals avoids leaking the configured key length/content through response timing.
            return CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(provided),
                Encoding.UTF8.GetBytes(configured));
        }
    }
}
