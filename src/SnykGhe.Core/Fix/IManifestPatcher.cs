namespace SnykGhe.Core.Fix
{
    /// <summary>
    /// Applies a <see cref="FixPlan"/> to the manifests of one ecosystem within a checked-out repo.
    /// Implementations are keyed by the policy's ecosystem id (e.g. "nuget").
    /// </summary>
    public interface IManifestPatcher
    {
        /// <summary>Ecosystem id this patcher handles, matching <c>ResolvedPolicy.Ecosystem</c>.</summary>
        string Ecosystem { get; }

        /// <summary>Returns the manifest files changed by applying the plan (empty if nothing matched).</summary>
        IReadOnlyList<PatchedFile> Apply(string workingDirectory, FixPlan plan);
    }
}
