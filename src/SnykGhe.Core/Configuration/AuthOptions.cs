namespace SnykGhe.Core.Configuration
{
    /// <summary>
    /// Authentication for the admin/management API (per-org Snyk mappings, per-repo overrides, manual
    /// scans, and the self-service registration entry point). Which methods are accepted is driven entirely
    /// by <see cref="Methods"/>: enable the legacy shared key (<c>AdminKey</c>), enterprise OAuth2/OIDC
    /// bearer tokens (<c>OAuth2</c>), or both. Any enabled method satisfies the request, so the two can run
    /// side by side during a migration. Configuration is validated at startup (see
    /// <see cref="AuthOptionsValidator"/>): the app refuses to start only on a genuine misconfiguration (an
    /// unknown method name, or OAuth2 without an authority/audience). An empty method set is allowed and
    /// simply leaves the admin API closed — a deployment configured entirely via app config that never calls
    /// the admin endpoints need not enable any method.
    /// </summary>
    public sealed class AuthOptions
    {
        public const string SectionName = "Auth";

        /// <summary>The legacy shared-secret method name (<c>X-Admin-Key</c> header).</summary>
        public const string AdminKeyMethod = "AdminKey";

        /// <summary>The OAuth2/OIDC JWT-bearer method name.</summary>
        public const string OAuth2Method = "OAuth2";

        /// <summary>
        /// Enabled authentication methods: any combination of <c>AdminKey</c> and <c>OAuth2</c>
        /// (case-insensitive). Each request to an admin endpoint is authorized if it satisfies <em>any</em>
        /// enabled method; an empty list leaves the admin API closed (no request can authenticate).
        /// </summary>
        public List<string> Methods { get; set; } = [];

        /// <summary>Shared-key settings, used only when <c>AdminKey</c> is in <see cref="Methods"/>.</summary>
        public AdminKeyOptions AdminKey { get; set; } = new();

        /// <summary>OAuth2/OIDC settings, used only when <c>OAuth2</c> is in <see cref="Methods"/>.</summary>
        public OAuth2Options OAuth2 { get; set; } = new();

        /// <summary>True when the named method is present in <see cref="Methods"/> (case-insensitive).</summary>
        public bool IsMethodEnabled(string method) =>
            Methods.Any(m => string.Equals(m?.Trim(), method, StringComparison.OrdinalIgnoreCase));

        /// <summary>True when the legacy shared-key method is enabled.</summary>
        public bool AdminKeyEnabled => IsMethodEnabled(AdminKeyMethod);

        /// <summary>True when the OAuth2/OIDC method is enabled.</summary>
        public bool OAuth2Enabled => IsMethodEnabled(OAuth2Method);
    }

    /// <summary>
    /// Settings for the <c>AdminKey</c> method — a shared secret sent in the <c>X-Admin-Key</c> header.
    /// Compared in constant time. A blank <see cref="Secret"/> closes the method (no caller can
    /// authenticate with it), rather than being a startup error.
    /// </summary>
    public sealed class AdminKeyOptions
    {
        /// <summary>
        /// The shared secret. Inject from Key Vault / Secrets Manager (never commit it) — typically via the
        /// deploy platform's secret reference, which resolves it into this config value at startup.
        /// </summary>
        public string? Secret { get; set; }
    }

    /// <summary>
    /// OAuth2/OIDC JWT-bearer validation settings. Vendor-agnostic: the app is a resource server that only
    /// <em>validates</em> tokens, so it works against any OIDC-compliant provider (Entra ID, Okta, Ping)
    /// that publishes a discovery document and issues JWT access tokens — no provider SDK (e.g. MSAL) is
    /// used. Tokens are validated by issuer (from discovery), audience, signature, and expiry.
    /// </summary>
    public sealed class OAuth2Options
    {
        /// <summary>
        /// The OIDC issuer / authority URL, e.g. <c>https://login.microsoftonline.com/&lt;tenant&gt;/v2.0</c>
        /// (Entra), <c>https://&lt;org&gt;.okta.com/oauth2/&lt;authz-server&gt;</c> (Okta), or the PingFederate
        /// issuer. The app reads <c>{Authority}/.well-known/openid-configuration</c> to discover the signing
        /// keys and issuer. Required when OAuth2 is enabled.
        /// </summary>
        public string? Authority { get; set; }

        /// <summary>
        /// The expected token audience (the API's resource identifier / application ID URI). A token whose
        /// <c>aud</c> does not match is rejected. Required when OAuth2 is enabled.
        /// </summary>
        public string? Audience { get; set; }

        /// <summary>
        /// Require the discovery/JWKS metadata to be fetched over HTTPS. Leave <c>true</c> in production;
        /// set <c>false</c> only for a local IdP served over plain HTTP during development.
        /// </summary>
        public bool RequireHttpsMetadata { get; set; } = true;

        /// <summary>
        /// Scopes that authorize an admin request. A token is authorized if it carries <em>any</em> of these
        /// scopes (see <see cref="ScopeClaimTypes"/>) <em>or</em> any required role. When both
        /// <see cref="RequiredScopes"/> and <see cref="RequiredRoles"/> are empty, any validly-issued token
        /// for the configured audience is accepted. Scope values are matched exactly (case-sensitive).
        /// </summary>
        public List<string> RequiredScopes { get; set; } = [];

        /// <summary>
        /// Roles/groups that authorize an admin request. A token is authorized if it carries <em>any</em> of
        /// these roles (see <see cref="RoleClaimTypes"/>) <em>or</em> any required scope. Consumers define
        /// the values to match their IdP (an Entra app role, an Okta/Ping group, etc.). Matched exactly.
        /// </summary>
        public List<string> RequiredRoles { get; set; } = [];

        /// <summary>
        /// JWT claim types inspected for scopes. Defaults cover the common providers: <c>scp</c> (Entra,
        /// Okta) and the standard space-delimited <c>scope</c>. A claim value containing spaces is split
        /// into individual scopes. Inbound claim mapping is disabled, so these are the raw JWT claim names.
        /// </summary>
        public List<string> ScopeClaimTypes { get; set; } = ["scp", "scope"];

        /// <summary>
        /// JWT claim types inspected for roles. Defaults cover the common providers: <c>roles</c> (Entra app
        /// roles), <c>role</c>, and <c>groups</c>. Override to match a custom claim your IdP emits.
        /// </summary>
        public List<string> RoleClaimTypes { get; set; } = ["roles", "role", "groups"];
    }
}
