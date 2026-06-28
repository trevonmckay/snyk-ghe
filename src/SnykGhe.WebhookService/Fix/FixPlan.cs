namespace SnykGhe.WebhookService.Fix
{
    /// <summary>A single direct-dependency version bump that resolves one or more vulnerabilities.</summary>
    public sealed record PackageUpgrade(
        string PackageName,
        string FromVersion,
        string ToVersion,
        IReadOnlyList<string> VulnerabilityIds);

    /// <summary>The set of upgrades to apply for a scan.</summary>
    public sealed class FixPlan
    {
        public required IReadOnlyList<PackageUpgrade> Upgrades { get; init; }

        public bool HasUpgrades => Upgrades.Count > 0;

        public static readonly FixPlan Empty = new() { Upgrades = [] };
    }

    /// <summary>A manifest file rewritten by a patcher, ready to commit.</summary>
    public sealed record PatchedFile(string RelativePath, string NewContent);
}
