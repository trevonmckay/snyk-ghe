using System.Text.Json;
using Snyk.Client.Tests;

namespace SnykGhe.Core.Snyk
{
    /// <summary>
    /// Projects Test API findings onto the shape <c>snyk test --json</c> produces, so the fix planner and
    /// Check Run rendering stay unaware of which engine performed the scan.
    /// </summary>
    public static class SnykApiFindingMapper
    {
        /// <summary>SAST findings are reported by the Code scanner, never as part of an Open Source result.</summary>
        public static SnykProjectResult ToProjectResult(string manifest, IReadOnlyList<SnykTestFinding> findings)
        {
            var vulnerabilities = findings
                .Where(f => !string.Equals(f.FindingType, "sast", StringComparison.OrdinalIgnoreCase))
                .Select(ToVulnerability)
                .ToList();

            return new SnykProjectResult
            {
                Ok = vulnerabilities.Count == 0,
                ProjectName = manifest,
                TargetFile = manifest,
                Vulnerabilities = vulnerabilities,
            };
        }

        /// <summary>
        /// <c>From</c> and <c>UpgradePath</c> are the two fields the fix planner reads: the former is the
        /// dependency path as it stands, the latter the same path carrying versions that resolve the issue.
        /// Index 1 of each is therefore the direct dependency to bump, and its target version.
        /// </summary>
        public static SnykVulnerability ToVulnerability(SnykTestFinding finding)
        {
            var fix = finding.Fix;

            return new SnykVulnerability
            {
                Id = PrimaryProblemId(finding),
                Title = finding.Title,
                Severity = finding.Severity,
                Type = IssueType(finding),
                PackageName = finding.Package?.Name ?? fix?.PackageName ?? string.Empty,
                Version = finding.Package?.Version ?? string.Empty,
                IsUpgradable = fix?.IsUpgradable ?? false,
                IsPatchable = false,
                FixedIn = finding.FixedInVersions.Count > 0 ? finding.FixedInVersions.ToList() : null,
                From = finding.DependencyPath.Count > 0
                    ? finding.DependencyPath.Select(p => p.ToString()).ToList()
                    : null,
                UpgradePath = fix is { IsUpgradable: true }
                    ? fix.UpgradePath.Select(p => JsonSerializer.SerializeToElement(p.ToString())).ToList()
                    : null,
            };
        }

        /// <summary>Prefers the Snyk vulnerability id (SNYK-…) over co-reported classifications such as CWE.</summary>
        private static string PrimaryProblemId(SnykTestFinding finding)
        {
            var snykProblem = finding.Problems.FirstOrDefault(
                p => string.Equals(p.Source, "snyk_vuln", StringComparison.OrdinalIgnoreCase));

            return snykProblem?.Id ?? finding.Problems.FirstOrDefault()?.Id ?? finding.Key;
        }

        /// <summary>
        /// The summary comment splits Open Source findings into vulnerabilities and license issues, keyed off
        /// the CLI's "vuln"/"license" issue type.
        /// </summary>
        private static string IssueType(SnykTestFinding finding) =>
            string.Equals(finding.FindingType, "license", StringComparison.OrdinalIgnoreCase) ? "license" : "vuln";
    }
}
