using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using SnykGhe.Core.Configuration;
using SnykGhe.Service.Authentication;

namespace SnykGhe.Core.Tests
{
    public class AdminAuthorizationTests
    {
        private static ClaimsPrincipal OAuthUser(params Claim[] claims) =>
            new(new ClaimsIdentity(claims, AuthOptions.OAuth2Method));

        private static ClaimsPrincipal AdminKeyUser() =>
            new(new ClaimsIdentity([], AdminKeyAuthenticationHandler.SchemeName));

        [Fact]
        public void NoScopeOrRoleRequired_AnyAuthenticatedToken_Authorized()
        {
            var oauth2 = new OAuth2Options();
            Assert.True(AdminAuthorization.IsOAuth2PrincipalAuthorized(OAuthUser(), oauth2));
        }

        [Fact]
        public void Unauthenticated_NotAuthorized()
        {
            var oauth2 = new OAuth2Options();
            Assert.False(AdminAuthorization.IsOAuth2PrincipalAuthorized(new ClaimsPrincipal(new ClaimsIdentity()), oauth2));
        }

        [Fact]
        public void RequiredScope_PresentInScpClaim_Authorized()
        {
            var oauth2 = new OAuth2Options { RequiredScopes = ["snykghe.admin"] };
            var user = OAuthUser(new Claim("scp", "snykghe.admin"));
            Assert.True(AdminAuthorization.IsOAuth2PrincipalAuthorized(user, oauth2));
        }

        [Fact]
        public void RequiredScope_PresentInSpaceDelimitedScopeClaim_Authorized()
        {
            var oauth2 = new OAuth2Options { RequiredScopes = ["snykghe.admin"] };
            var user = OAuthUser(new Claim("scope", "openid profile snykghe.admin"));
            Assert.True(AdminAuthorization.IsOAuth2PrincipalAuthorized(user, oauth2));
        }

        [Fact]
        public void RequiredRole_PresentInRolesClaim_Authorized()
        {
            var oauth2 = new OAuth2Options { RequiredRoles = ["SnykGheAdmin"] };
            var user = OAuthUser(new Claim("roles", "SnykGheAdmin"));
            Assert.True(AdminAuthorization.IsOAuth2PrincipalAuthorized(user, oauth2));
        }

        [Fact]
        public void ScopeOrRole_RoleSatisfiesEvenWithoutScope_Authorized()
        {
            var oauth2 = new OAuth2Options { RequiredScopes = ["snykghe.admin"], RequiredRoles = ["SnykGheAdmin"] };
            var user = OAuthUser(new Claim("groups", "SnykGheAdmin"));
            Assert.True(AdminAuthorization.IsOAuth2PrincipalAuthorized(user, oauth2));
        }

        [Fact]
        public void RequiredScopeOrRole_NeitherPresent_NotAuthorized()
        {
            var oauth2 = new OAuth2Options { RequiredScopes = ["snykghe.admin"], RequiredRoles = ["SnykGheAdmin"] };
            var user = OAuthUser(new Claim("scp", "some.other.scope"), new Claim("roles", "SomeOtherRole"));
            Assert.False(AdminAuthorization.IsOAuth2PrincipalAuthorized(user, oauth2));
        }

        [Fact]
        public void Scope_MatchIsCaseSensitive()
        {
            var oauth2 = new OAuth2Options { RequiredScopes = ["snykghe.admin"] };
            var user = OAuthUser(new Claim("scp", "SNYKGHE.ADMIN"));
            Assert.False(AdminAuthorization.IsOAuth2PrincipalAuthorized(user, oauth2));
        }

        [Fact]
        public void AdminKeyPrincipal_BypassesScopeRoleGate()
        {
            // The admin key is fully trusted; a scope/role requirement configured for OAuth2 must not apply.
            var oauth2 = new OAuth2Options { RequiredScopes = ["snykghe.admin"] };
            var context = new AuthorizationHandlerContext([], AdminKeyUser(), resource: null);
            Assert.True(AdminAuthorization.IsAuthorized(context, oauth2));
        }

        [Fact]
        public void OAuth2Principal_ThroughIsAuthorized_AppliesGate()
        {
            var oauth2 = new OAuth2Options { RequiredScopes = ["snykghe.admin"] };
            var context = new AuthorizationHandlerContext([], OAuthUser(new Claim("scp", "wrong")), resource: null);
            Assert.False(AdminAuthorization.IsAuthorized(context, oauth2));
        }
    }
}
