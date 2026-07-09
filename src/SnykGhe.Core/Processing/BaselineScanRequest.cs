using System.Text.Json.Serialization;

namespace SnykGhe.Core.Processing
{
    /// <summary>
    /// A unit of work: scan a repository's default branch and persist a Snyk monitor snapshot under that
    /// branch's target reference. Unlike <see cref="ScanRequest"/> there is no pull request — no Check Run,
    /// summary comment, or fix PR — the baseline exists to keep the shipped branch's monitored snapshot current.
    /// </summary>
    public sealed record BaselineScanRequest
    {
        public required long InstallationId { get; init; }

        public required string Owner { get; init; }

        public required string Repo { get; init; }

        public required string CloneUrl { get; init; }

        /// <summary>The default branch name, used both as the clone ref and the Snyk <c>--target-reference</c>.</summary>
        public required string Branch { get; init; }

        public required string HeadSha { get; init; }

        /// <summary>The clone URL normalized to the Snyk target name (trailing <c>.git</c> removed).</summary>
        [JsonIgnore]
        public string RemoteRepoUrl => ScanRequest.NormalizeRemoteRepoUrl(CloneUrl);
    }
}
