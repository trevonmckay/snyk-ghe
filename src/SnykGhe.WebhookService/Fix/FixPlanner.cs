using System.Text.Json;
using NuGet.Versioning;
using SnykGhe.WebhookService.Snyk;

namespace SnykGhe.WebhookService.Fix
{
    /// <summary>
    /// Derives direct-dependency version bumps from Snyk's per-vulnerability upgrade data.
    /// Each vulnerability's <c>from</c>/<c>upgradePath</c> identifies the direct dependency to raise and
    /// the target version that resolves it (including transitive issues fixed by bumping a direct dep).
    /// </summary>
    public sealed class FixPlanner
    {
        public FixPlan Plan(SnykScanResult scan)
        {
            if (scan.Failed)
            {
                return FixPlan.Empty;
            }

            // package name (case-insensitive) -> aggregated upgrade
            var aggregated = new Dictionary<string, (string From, NuGetVersion? To, string ToRaw, HashSet<string> Vulns)>(
                StringComparer.OrdinalIgnoreCase);

            foreach (var vuln in scan.AllVulnerabilities)
            {
                if (!vuln.IsUpgradable || vuln.From is not { Count: >= 2 } from || vuln.UpgradePath is not { Count: >= 2 } path)
                {
                    continue;
                }

                // The direct dependency is index 1; its upgrade target is upgradePath[1] when concrete.
                if (path[1].ValueKind != JsonValueKind.String)
                {
                    continue;
                }

                if (!TrySplit(from[1], out var directName, out var fromVersion) ||
                    !TrySplit(path[1].GetString(), out var targetName, out var toVersion) ||
                    !directName.Equals(targetName, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                NuGetVersion.TryParse(toVersion, out var parsedTo);

                if (aggregated.TryGetValue(directName, out var existing))
                {
                    // Keep the highest target version that satisfies every vulnerability for this package.
                    var keepNew = existing.To is null || (parsedTo is not null && parsedTo > existing.To);
                    existing.Vulns.Add(vuln.Id);
                    aggregated[directName] = keepNew
                        ? (fromVersion, parsedTo, toVersion, existing.Vulns)
                        : existing;
                }
                else
                {
                    aggregated[directName] = (fromVersion, parsedTo, toVersion, [vuln.Id]);
                }
            }

            var upgrades = aggregated
                .Select(kvp => new PackageUpgrade(kvp.Key, kvp.Value.From, kvp.Value.ToRaw, kvp.Value.Vulns.ToList()))
                .OrderBy(u => u.PackageName, StringComparer.OrdinalIgnoreCase)
                .ToList();

            return new FixPlan { Upgrades = upgrades };
        }

        private static bool TrySplit(string? packageAtVersion, out string name, out string version)
        {
            name = string.Empty;
            version = string.Empty;

            if (string.IsNullOrEmpty(packageAtVersion))
            {
                return false;
            }

            var at = packageAtVersion.LastIndexOf('@');
            if (at <= 0 || at == packageAtVersion.Length - 1)
            {
                return false;
            }

            name = packageAtVersion[..at];
            version = packageAtVersion[(at + 1)..];
            return true;
        }
    }
}
