namespace SnykGhe.Core.Fix
{
    /// <summary>A single direct-dependency version bump that resolves one or more vulnerabilities.</summary>
    public sealed record PackageUpgrade
    {
        public required string PackageName { get; init; }
        public required string FromVersion { get; init; }
        public required string ToVersion { get; init; }
        public required IReadOnlyList<string> VulnerabilityIds { get; init; }
    }

    /// <summary>The set of upgrades to apply for a scan.</summary>
    public sealed class FixPlan
    {
        public required IReadOnlyList<PackageUpgrade> Upgrades { get; init; }

        public bool HasUpgrades => Upgrades.Count > 0;

        public static readonly FixPlan Empty = new() { Upgrades = [] };
    }

    /// <summary>A manifest file rewritten by a patcher, ready to commit.</summary>
    public sealed record PatchedFile
    {
        public required string RelativePath { get; init; }
        public required string NewContent { get; init; }
    }
}
