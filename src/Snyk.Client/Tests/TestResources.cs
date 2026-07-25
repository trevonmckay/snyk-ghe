using System.Text.Json.Nodes;

namespace Snyk.Client.Tests
{
    /// <summary>Snyk scanners selectable on a test's scan configuration.</summary>
    public enum SnykScanner
    {
        Sca,
        Sast,
        Iac,
        Container,
        Secrets,
    }

    /// <summary>SDLC stage a test was initiated from; recorded on the test for reporting.</summary>
    public enum SdlcStage
    {
        Ide,
        Cli,
        PrCheck,
        CiCd,
        Mcp,
        Other,
    }

    /// <summary>
    /// Where a resource's content came from. This describes provenance only — the resource itself remains the
    /// testable item — and <see cref="ScmRepositoryResource"/> does not use it, identifying its SCM by its own
    /// fields instead.
    /// </summary>
    public sealed class SnykScmContext
    {
        public string? RepositoryUrl { get; init; }

        public string? Branch { get; init; }

        public string? CommitRef { get; init; }

        internal JsonObject? ToJson()
        {
            var context = new JsonObject();

            if (!string.IsNullOrWhiteSpace(Branch))
            {
                context["branch"] = Branch;
            }

            if (!string.IsNullOrWhiteSpace(CommitRef))
            {
                context["commit_ref"] = CommitRef;
            }

            if (!string.IsNullOrWhiteSpace(RepositoryUrl))
            {
                context["repo_url"] = RepositoryUrl;
            }

            return context.Count > 0 ? context : null;
        }
    }

    /// <summary>
    /// A unit of testable content submitted with a test. Not every scanner accepts every resource: Snyk
    /// pairs resources with scan configurations by "best fit" and fails the assembled test when no valid
    /// combination exists. That failure surfaces on the completed job, not on the create call.
    /// </summary>
    public abstract class TestResource
    {
        /// <summary>Serializes this resource into the <c>resources[]</c> element the API expects.</summary>
        internal abstract JsonObject ToJson();

        /// <summary>Wraps the concrete resource in the "base" (non-diff) envelope.</summary>
        protected static JsonObject BaseEnvelope(JsonObject resource) =>
            new() { ["type"] = "base", ["resource"] = resource };
    }

    /// <summary>
    /// Dependency-graph contents sent inline in the request body. This is the only SCA input that requires
    /// nothing to be pre-registered with Snyk, so it is the one that works from a plain working copy.
    /// </summary>
    public sealed class InlineDepGraphResource : TestResource
    {
        /// <summary>Name attributed to the graph, e.g. the manifest file it was derived from.</summary>
        public required string Name { get; init; }

        /// <summary>A Snyk dep-graph document (<c>schemaVersion</c>, <c>pkgManager</c>, <c>pkgs</c>, <c>graph</c>).</summary>
        public required JsonNode DepGraph { get; init; }

        /// <summary>Optional provenance for the graph — the repository and reference it was built from.</summary>
        public SnykScmContext? ScmContext { get; init; }

        internal override JsonObject ToJson()
        {
            var resource = new JsonObject
            {
                ["type"] = "inline",
                ["name"] = Name,
                ["content"] = new JsonObject
                {
                    ["type"] = "dep_graph",
                    ["dep_graph"] = DepGraph.DeepClone(),
                },
            };

            if (ScmContext?.ToJson() is { } context)
            {
                resource["scm_context"] = context;
            }

            return BaseEnvelope(resource);
        }
    }

    /// <summary>
    /// A repository reachable through a Snyk SCM integration. The repository must already be imported into
    /// Snyk under that integration; a target created by the CLI does not qualify and the test fails with
    /// <c>SNYK-TARGET-0001: Target not found</c>.
    /// </summary>
    public sealed class ScmRepositoryResource : TestResource
    {
        public required string RepositoryUrl { get; init; }

        /// <summary>Integration id from Snyk's org settings, identifying which SCM connection to read through.</summary>
        public required string IntegrationId { get; init; }

        /// <summary>Branch or other non-commit reference to test.</summary>
        public string? Reference { get; init; }

        /// <summary>Exact commit to test; takes precedence over <see cref="Reference"/> when Snyk resolves content.</summary>
        public string? Commit { get; init; }

        internal override JsonObject ToJson()
        {
            var resource = new JsonObject
            {
                ["type"] = "scm",
                ["repo_url"] = RepositoryUrl,
                ["integration_id"] = IntegrationId,
                // The API requires the key to be present even though patterns are not yet supported.
                ["file_patterns"] = new JsonArray(),
            };

            if (!string.IsNullOrWhiteSpace(Reference))
            {
                resource["ref"] = Reference;
            }

            if (!string.IsNullOrWhiteSpace(Commit))
            {
                resource["commit"] = Commit;
            }

            return BaseEnvelope(resource);
        }
    }

    /// <summary>Content already known to Snyk as a Target or Project.</summary>
    public sealed class SnykReferenceResource : TestResource
    {
        public required string ReferenceId { get; init; }

        /// <summary>One of <c>target</c>, <c>project</c>, or <c>asset</c>.</summary>
        public required string ReferenceType { get; init; }

        /// <summary>Optional provenance for the referenced content.</summary>
        public SnykScmContext? ScmContext { get; init; }

        internal override JsonObject ToJson()
        {
            var resource = new JsonObject
            {
                ["type"] = "snyk_ref",
                ["reference_type"] = ReferenceType,
                ["ref_id"] = ReferenceId,
            };

            if (ScmContext?.ToJson() is { } context)
            {
                resource["scm_context"] = context;
            }

            return BaseEnvelope(resource);
        }
    }

    /// <summary>A collection of files previously uploaded to Snyk as a bundle. SAST requires exactly one.</summary>
    public sealed class BundleResource : TestResource
    {
        public required string BundleId { get; init; }

        /// <summary>Either <c>sbom</c> or <c>source</c>.</summary>
        public required string ContentType { get; init; }

        public string? Name { get; init; }

        public string? RepositoryUrl { get; init; }

        public string? RootFolderId { get; init; }

        internal override JsonObject ToJson()
        {
            var resource = new JsonObject
            {
                ["type"] = "bundle",
                ["bundle_id"] = BundleId,
                ["content_type"] = ContentType,
                ["file_patterns"] = new JsonArray(),
            };

            if (!string.IsNullOrWhiteSpace(Name))
            {
                resource["name"] = Name;
            }

            if (!string.IsNullOrWhiteSpace(RepositoryUrl))
            {
                resource["repository_url"] = RepositoryUrl;
            }

            if (!string.IsNullOrWhiteSpace(RootFolderId))
            {
                resource["root_folder_id"] = RootFolderId;
            }

            return BaseEnvelope(resource);
        }
    }
}
