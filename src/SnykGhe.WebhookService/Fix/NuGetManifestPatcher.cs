using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace SnykGhe.WebhookService.Fix
{
    /// <summary>
    /// Bumps NuGet package versions in SDK-style <c>PackageReference</c> items, central
    /// <c>Directory.Packages.props</c> (<c>PackageVersion</c>), and legacy <c>packages.config</c>.
    /// Matching is namespace-agnostic (legacy csproj uses the MSBuild XML namespace; SDK-style does not).
    /// </summary>
    public sealed class NuGetManifestPatcher : IManifestPatcher
    {
        public string Ecosystem => "nuget";

        public IReadOnlyList<PatchedFile> Apply(string workingDirectory, FixPlan plan)
        {
            if (!plan.HasUpgrades)
            {
                return [];
            }

            var targets = plan.Upgrades.ToDictionary(u => u.PackageName, u => u.ToVersion, StringComparer.OrdinalIgnoreCase);
            var patched = new List<PatchedFile>();

            foreach (var file in EnumerateManifests(workingDirectory))
            {
                if (TryPatchFile(file, targets, out var newContent))
                {
                    var relative = Path.GetRelativePath(workingDirectory, file).Replace('\\', '/');
                    patched.Add(new PatchedFile(relative, newContent));
                }
            }

            return patched;
        }

        private static IEnumerable<string> EnumerateManifests(string root)
        {
            foreach (var pattern in new[] { "*.csproj", "*.props", "packages.config" })
            {
                foreach (var path in Directory.EnumerateFiles(root, pattern, SearchOption.AllDirectories))
                {
                    yield return path;
                }
            }
        }

        private static bool TryPatchFile(string path, IReadOnlyDictionary<string, string> targets, out string newContent)
        {
            newContent = string.Empty;

            XDocument doc;
            try
            {
                doc = XDocument.Load(path, LoadOptions.PreserveWhitespace);
            }
            catch (XmlException)
            {
                return false;
            }

            var changed = false;

            foreach (var element in doc.Descendants())
            {
                changed |= element.Name.LocalName switch
                {
                    "PackageReference" or "PackageVersion" => TryUpdatePackageElement(element, targets),
                    "package" => TryUpdatePackagesConfigEntry(element, targets),
                    _ => false,
                };
            }

            if (!changed)
            {
                return false;
            }

            newContent = Serialize(doc);
            return true;
        }

        private static bool TryUpdatePackageElement(XElement element, IReadOnlyDictionary<string, string> targets)
        {
            var id = AttributeByLocalName(element, "Include") ?? AttributeByLocalName(element, "Update");
            if (id?.Value is not { } name || !targets.TryGetValue(name, out var target))
            {
                return false;
            }

            // Version may be an attribute or a child element.
            var versionAttr = element.Attributes().FirstOrDefault(a => a.Name.LocalName == "Version");
            if (versionAttr is not null)
            {
                return SetIfDifferent(() => versionAttr.Value, v => versionAttr.Value = v, target);
            }

            var versionChild = element.Elements().FirstOrDefault(e => e.Name.LocalName == "Version");
            if (versionChild is not null)
            {
                return SetIfDifferent(() => versionChild.Value, v => versionChild.Value = v, target);
            }

            return false;
        }

        private static bool TryUpdatePackagesConfigEntry(XElement element, IReadOnlyDictionary<string, string> targets)
        {
            var id = AttributeByLocalName(element, "id");
            var versionAttr = element.Attributes().FirstOrDefault(a => a.Name.LocalName == "version");
            if (id?.Value is not { } name || versionAttr is null || !targets.TryGetValue(name, out var target))
            {
                return false;
            }

            return SetIfDifferent(() => versionAttr.Value, v => versionAttr.Value = v, target);
        }

        private static XAttribute? AttributeByLocalName(XElement element, string localName) =>
            element.Attributes().FirstOrDefault(a => a.Name.LocalName == localName);

        private static bool SetIfDifferent(Func<string> get, Action<string> set, string target)
        {
            if (string.Equals(get(), target, StringComparison.Ordinal))
            {
                return false;
            }

            set(target);
            return true;
        }

        private static string Serialize(XDocument doc)
        {
            var builder = new StringBuilder();
            var settings = new XmlWriterSettings
            {
                OmitXmlDeclaration = doc.Declaration is null,
                Encoding = new UTF8Encoding(false),
                // PreserveWhitespace kept the original layout; do not re-indent.
            };

            using (var writer = XmlWriter.Create(builder, settings))
            {
                doc.Save(writer);
            }

            return builder.ToString();
        }
    }
}
