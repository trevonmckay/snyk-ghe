using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using SnykGhe.Core.Configuration;

namespace SnykGhe.Core.GitHub.Manifest
{
    /// <summary>
    /// Issues and validates a short-lived signed token tying the manifest-creation redirect back to a
    /// request that began at the admin-gated /register endpoint. Without it, a forged /created callback
    /// could convert an attacker-created App and overwrite the real credentials in the secret store. The
    /// admin key is the HMAC signing key, so a valid token can only originate from someone who passed the
    /// admin gate.
    /// </summary>
    public sealed class RegistrationStateProtector
    {
        private readonly byte[] _key;

        public RegistrationStateProtector(IOptions<StorageOptions> storage)
        {
            _key = Encoding.UTF8.GetBytes(storage.Value.AdminApiKey ?? string.Empty);
        }

        /// <summary>False when no admin key is set; the registration flow is then disabled entirely.</summary>
        public bool IsEnabled => _key.Length > 0;

        public string Issue()
        {
            var seconds = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
            var payload = $"{seconds}.{nonce}";
            return $"{payload}.{Sign(payload)}";
        }

        public bool Validate(string? state, TimeSpan maxAge)
        {
            if (!IsEnabled || string.IsNullOrEmpty(state))
            {
                return false;
            }

            var parts = state.Split('.');
            if (parts.Length != 3)
            {
                return false;
            }

            var payload = $"{parts[0]}.{parts[1]}";
            if (!CryptographicOperations.FixedTimeEquals(
                    Encoding.ASCII.GetBytes(Sign(payload)), Encoding.ASCII.GetBytes(parts[2])))
            {
                return false;
            }

            if (!long.TryParse(parts[0], out var seconds))
            {
                return false;
            }

            var age = DateTimeOffset.UtcNow - DateTimeOffset.FromUnixTimeSeconds(seconds);
            return age >= TimeSpan.Zero && age <= maxAge;
        }

        private string Sign(string payload)
        {
            using var hmac = new HMACSHA256(_key);
            return Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(payload)));
        }
    }
}
