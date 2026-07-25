using System.Text.Json;

namespace Snyk.Client.Resources
{
    /// <summary>A Snyk organization.</summary>
    public sealed class SnykOrg
    {
        public required string Id { get; init; }

        public string? Slug { get; init; }

        public string? Name { get; init; }
    }

    /// <summary>A Snyk project: one manifest or scan unit under a target.</summary>
    public sealed class SnykProject
    {
        public required string Id { get; init; }

        public string? Name { get; init; }

        /// <summary>Project type, e.g. <c>nuget</c>, <c>npm</c>, <c>sast</c>.</summary>
        public string? Type { get; init; }

        /// <summary>Reference (typically a branch) grouping this project's snapshots.</summary>
        public string? TargetReference { get; init; }
    }

    /// <summary>A Snyk target: a repository or image that projects hang off.</summary>
    public sealed class SnykTarget
    {
        public required string Id { get; init; }

        public string? DisplayName { get; init; }

        public string? Url { get; init; }

        /// <summary>
        /// How the target was created: <c>cli</c> for one published by <c>snyk monitor</c>, or an SCM type
        /// such as <c>github-enterprise</c> for one imported through an integration. Scans that read source
        /// through an integration only accept targets imported by that integration.
        /// </summary>
        public string? IntegrationType { get; init; }

        public string? IntegrationId { get; init; }
    }

    /// <summary>Reads organizations.</summary>
    public sealed class SnykOrgsApi
    {
        private readonly SnykHttpTransport _transport;

        internal SnykOrgsApi(SnykHttpTransport transport)
        {
            _transport = transport;
        }

        public async Task<SnykOrg?> GetAsync(string orgId, CancellationToken cancellationToken = default)
        {
            var url = _transport.BuildUrl($"/orgs/{Uri.EscapeDataString(orgId)}");

            using var doc = await _transport.GetOrNullAsync(url, cancellationToken);
            if (doc is null || !doc.RootElement.TryGetProperty("data", out var data))
            {
                return null;
            }

            var attributes = data.TryGetProperty("attributes", out var a) ? a : default;

            return new SnykOrg
            {
                Id = data.GetProperty("id").GetString() ?? orgId,
                Slug = JsonReader.Str(attributes, "slug"),
                Name = JsonReader.Str(attributes, "name"),
            };
        }
    }

    /// <summary>Filter for a project listing. Omitted values are not sent.</summary>
    public sealed class SnykProjectFilter
    {
        public string? Name { get; init; }

        /// <summary>Comma-separated project types, e.g. <c>sast</c>.</summary>
        public string? Types { get; init; }

        public string? TargetId { get; init; }

        public string? TargetReference { get; init; }
    }

    /// <summary>Lists and deletes projects.</summary>
    public sealed class SnykProjectsApi
    {
        private readonly SnykHttpTransport _transport;

        internal SnykProjectsApi(SnykHttpTransport transport)
        {
            _transport = transport;
        }

        public async Task<IReadOnlyList<SnykProject>> ListAsync(
            string orgId,
            SnykProjectFilter? filter = null,
            CancellationToken cancellationToken = default)
        {
            filter ??= new SnykProjectFilter();

            var url = _transport.BuildUrl(
                $"/orgs/{Uri.EscapeDataString(orgId)}/projects",
                ("names", filter.Name),
                ("types", filter.Types),
                ("target_id", filter.TargetId),
                ("target_reference", filter.TargetReference),
                ("limit", _transport.Options.PageSize.ToString()));

            var items = await _transport.GetPagedAsync(url, cancellationToken);

            var projects = new List<SnykProject>(items.Count);
            foreach (var item in items)
            {
                var attributes = item.TryGetProperty("attributes", out var a) ? a : default;
                projects.Add(new SnykProject
                {
                    Id = item.GetProperty("id").GetString() ?? string.Empty,
                    Name = JsonReader.Str(attributes, "name"),
                    Type = JsonReader.Str(attributes, "type"),
                    TargetReference = JsonReader.Str(attributes, "target_reference"),
                });
            }

            return projects;
        }

        public Task<bool> DeleteAsync(string orgId, string projectId, CancellationToken cancellationToken = default)
        {
            var url = _transport.BuildUrl(
                $"/orgs/{Uri.EscapeDataString(orgId)}/projects/{Uri.EscapeDataString(projectId)}");
            return _transport.DeleteAsync(url, cancellationToken);
        }
    }

    /// <summary>Lists and deletes targets.</summary>
    public sealed class SnykTargetsApi
    {
        private readonly SnykHttpTransport _transport;

        internal SnykTargetsApi(SnykHttpTransport transport)
        {
            _transport = transport;
        }

        /// <summary>
        /// Lists targets, optionally filtered by repository URL. The server-side <c>url</c> filter matches
        /// rather than compares exactly, so callers that need an exact repository must check
        /// <see cref="SnykTarget.Url"/> themselves.
        /// </summary>
        public async Task<IReadOnlyList<SnykTarget>> ListAsync(
            string orgId,
            string? url = null,
            CancellationToken cancellationToken = default)
        {
            var requestUrl = _transport.BuildUrl(
                $"/orgs/{Uri.EscapeDataString(orgId)}/targets",
                ("url", url),
                ("limit", _transport.Options.PageSize.ToString()));

            var items = await _transport.GetPagedAsync(requestUrl, cancellationToken);

            var targets = new List<SnykTarget>(items.Count);
            foreach (var item in items)
            {
                var attributes = item.TryGetProperty("attributes", out var a) ? a : default;
                var integration = item.TryGetProperty("relationships", out var r)
                    && r.TryGetProperty("integration", out var i)
                    && i.TryGetProperty("data", out var d)
                        ? d
                        : default;

                targets.Add(new SnykTarget
                {
                    Id = item.GetProperty("id").GetString() ?? string.Empty,
                    DisplayName = JsonReader.Str(attributes, "display_name"),
                    Url = JsonReader.Str(attributes, "url"),
                    IntegrationId = JsonReader.Str(integration, "id"),
                    IntegrationType = integration.ValueKind == JsonValueKind.Object
                        && integration.TryGetProperty("attributes", out var ia)
                            ? JsonReader.Str(ia, "integration_type")
                            : null,
                });
            }

            return targets;
        }

        public Task<bool> DeleteAsync(string orgId, string targetId, CancellationToken cancellationToken = default)
        {
            var url = _transport.BuildUrl(
                $"/orgs/{Uri.EscapeDataString(orgId)}/targets/{Uri.EscapeDataString(targetId)}");
            return _transport.DeleteAsync(url, cancellationToken);
        }
    }

    internal static class JsonReader
    {
        internal static string? Str(JsonElement element, string property) =>
            element.ValueKind == JsonValueKind.Object
                && element.TryGetProperty(property, out var value)
                && value.ValueKind == JsonValueKind.String
                    ? value.GetString()
                    : null;
    }
}
