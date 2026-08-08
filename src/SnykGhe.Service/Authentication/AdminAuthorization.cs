using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using SnykGhe.Core.Configuration;

namespace SnykGhe.Service.Authentication
{
    /// <summary>
    /// The authorization policy guarding the admin/management API, plus the scope/role gate applied to
    /// OAuth2 principals. A request is authorized when it satisfies any enabled authentication scheme and:
    /// <list type="bullet">
    /// <item>it was authenticated by the admin key — a fully-trusted credential, no further gate; or</item>
    /// <item>it is an OAuth2 bearer token that carries a required scope <em>or</em> a required role. When no
    /// required scopes and no required roles are configured, any validly-issued token is accepted.</item>
    /// </list>
    /// </summary>
    public static class AdminAuthorization
    {
        public const string PolicyName = "AdminAccess";

        /// <summary>Authorization callback for the <see cref="PolicyName"/> policy.</summary>
        public static bool IsAuthorized(AuthorizationHandlerContext context, OAuth2Options oauth2)
        {
            // The admin key is a fully-trusted credential; scope/role gating applies only to OAuth2 tokens.
            if (context.User.Identities.Any(i =>
                    i.IsAuthenticated && i.AuthenticationType == AdminKeyAuthenticationHandler.SchemeName))
            {
                return true;
            }

            return IsOAuth2PrincipalAuthorized(context.User, oauth2);
        }

        /// <summary>
        /// Applies the scope-or-role gate to an OAuth2 principal. Empty scope and role config means any
        /// validly-issued token (correct issuer/audience/signature, already enforced by JWT validation) is
        /// accepted. Exposed for unit testing the gate in isolation.
        /// </summary>
        public static bool IsOAuth2PrincipalAuthorized(ClaimsPrincipal user, OAuth2Options oauth2)
        {
            if (user.Identity?.IsAuthenticated != true)
            {
                return false;
            }

            if (oauth2.RequiredScopes.Count == 0 && oauth2.RequiredRoles.Count == 0)
            {
                return true;
            }

            return HasAny(user, oauth2.ScopeClaimTypes, oauth2.RequiredScopes, splitOnSpaces: true)
                || HasAny(user, oauth2.RoleClaimTypes, oauth2.RequiredRoles, splitOnSpaces: false);
        }

        private static bool HasAny(
            ClaimsPrincipal user,
            IReadOnlyList<string> claimTypes,
            IReadOnlyList<string> required,
            bool splitOnSpaces)
        {
            if (required.Count == 0)
            {
                return false;
            }

            var present = new HashSet<string>(StringComparer.Ordinal);
            foreach (var claimType in claimTypes)
            {
                foreach (var claim in user.FindAll(claimType))
                {
                    if (splitOnSpaces)
                    {
                        foreach (var value in claim.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                        {
                            present.Add(value);
                        }
                    }
                    else
                    {
                        present.Add(claim.Value);
                    }
                }
            }

            return required.Any(present.Contains);
        }
    }
}
