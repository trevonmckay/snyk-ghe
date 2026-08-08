using Microsoft.Extensions.Options;

namespace SnykGhe.Core.Configuration
{
    /// <summary>
    /// Fail-fast validation for <see cref="AuthOptions"/>, run at startup (via <c>ValidateOnStart</c>). Only
    /// genuine misconfigurations are hard errors: an unrecognized method name (a typo that would silently do
    /// nothing), or an <c>OAuth2</c> method with no authority/audience to validate against. States that
    /// merely leave the admin API <em>closed</em> are allowed and start normally — an empty
    /// <see cref="AuthOptions.Methods"/>, or <c>AdminKey</c> enabled with a blank
    /// <see cref="AdminKeyOptions.Secret"/> — because a deployment configured entirely via app config may
    /// never call the admin endpoints.
    /// </summary>
    public sealed class AuthOptionsValidator : IValidateOptions<AuthOptions>
    {
        private static readonly string[] RecognizedMethods = [AuthOptions.AdminKeyMethod, AuthOptions.OAuth2Method];

        public ValidateOptionsResult Validate(string? name, AuthOptions options)
        {
            var errors = new List<string>();

            var methods = options.Methods.Where(m => !string.IsNullOrWhiteSpace(m)).ToList();

            var unknown = methods
                .Where(m => !RecognizedMethods.Contains(m.Trim(), StringComparer.OrdinalIgnoreCase))
                .ToList();
            if (unknown.Count > 0)
            {
                errors.Add(
                    $"Auth:Methods contains unknown method(s): {string.Join(", ", unknown)}. " +
                    $"Valid values are: {string.Join(", ", RecognizedMethods)}.");
            }

            if (options.OAuth2Enabled)
            {
                if (string.IsNullOrWhiteSpace(options.OAuth2.Authority))
                {
                    errors.Add(
                        $"Auth:Methods includes '{AuthOptions.OAuth2Method}' but Auth:OAuth2:Authority is not set " +
                        "(the OIDC issuer URL, e.g. https://login.microsoftonline.com/<tenant>/v2.0).");
                }

                if (string.IsNullOrWhiteSpace(options.OAuth2.Audience))
                {
                    errors.Add(
                        $"Auth:Methods includes '{AuthOptions.OAuth2Method}' but Auth:OAuth2:Audience is not set " +
                        "(the API's resource identifier / application ID URI that tokens must target).");
                }
            }

            return errors.Count == 0
                ? ValidateOptionsResult.Success
                : ValidateOptionsResult.Fail(errors);
        }
    }
}
