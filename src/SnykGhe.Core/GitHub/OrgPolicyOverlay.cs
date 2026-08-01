namespace SnykGhe.Core.GitHub
{
    /// <summary>
    /// The authoritative per-org policy state written by the admin API. Every field is the desired final
    /// value: a null <see cref="SnykOrgId"/>, <see cref="SeverityThreshold"/>, or <see cref="Ecosystem"/>
    /// clears that override so the resolver falls back to the global default, and an empty
    /// <see cref="ExcludeDirs"/> clears the org exclude list. The registry preserves the GitHub-seeded fields
    /// (installation id, account id) that the installation webhook owns.
    /// </summary>
    public sealed class OrgPolicyOverlay
    {
        public string? SnykOrgId { get; set; }

        public string? SeverityThreshold { get; set; }

        public string? Ecosystem { get; set; }

        public bool Suspended { get; set; }

        public IReadOnlyList<string> ExcludeDirs { get; set; } = [];
    }
}
