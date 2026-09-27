using System.Text.Json;
using System.Text.Json.Nodes;

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

    /// <summary>A project a bulk-delete request removed.</summary>
    public sealed class SnykBulkDeletedProject
    {
        public required string Id { get; init; }

        public string? Name { get; init; }
    }

    /// <summary>A project a bulk-delete request did not remove, with the reason Snyk gave.</summary>
    public sealed class SnykBulkDeleteFailure
    {
        public required string Id { get; init; }

        public string? Name { get; init; }

        /// <summary>
        /// Snyk's reason code. Known values: <c>delete_failed</c> (the project itself could not be deleted),
        /// <c>exclusion_failed</c> and <c>exclusion_limit_reached</c> (only when the request asked to exclude
        /// the project's file from future scans). Left as the raw string so a reason added later is not lost.
        /// </summary>
        public string? Reason { get; init; }
    }

    /// <summary>The outcome of a bulk-delete request: the projects removed and those that were not.</summary>
    public sealed class SnykBulkDeleteResult
    {
        public required IReadOnlyList<SnykBulkDeletedProject> Deleted { get; init; }

        public required IReadOnlyList<SnykBulkDeleteFailure> Failed { get; init; }

        /// <summary>
        /// Requested project ids whose batch returned a success response without the <c>meta</c> summary, so
        /// whether Snyk deleted them is unknown. They appear in neither <see cref="Deleted"/> nor <see cref="Failed"/>.
        /// </summary>
        public required IReadOnlyList<string> Unreported { get; init; }
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

        /// <summary>Deletes a project. Idempotent: a missing project is treated as already deleted. Throws
        /// <see cref="SnykApiException"/> on a non-404 API failure so the caller can retry.</summary>
        public Task DeleteAsync(string orgId, string projectId, CancellationToken cancellationToken = default)
        {
            var url = _transport.BuildUrl(
                $"/orgs/{Uri.EscapeDataString(orgId)}/projects/{Uri.EscapeDataString(projectId)}");
            return _transport.DeleteAsync(url, cancellationToken);
        }

        /// <summary>The Snyk bulk-delete endpoint accepts at most this many projects per request.</summary>
        private const int BulkDeleteBatchSize = 100;

        /// <summary>
        /// Deletes projects in bulk, batching into requests of at most 100 (the endpoint's per-request cap) and
        /// aggregating the outcomes. Unlike <see cref="DeleteAsync"/>, a project the endpoint could not delete is
        /// reported in <see cref="SnykBulkDeleteResult.Failed"/> rather than raising — the request as a whole
        /// still succeeds — so the caller decides how to treat a partial failure. A project that does not exist
        /// in the org is ignored by Snyk and appears in neither list. A request the API rejects outright (any
        /// non-2xx, e.g. a 404 for a missing org or an API version that predates the endpoint, a 429, or a 5xx)
        /// still throws <see cref="SnykApiException"/>. A 2xx without a readable <c>meta</c> summary (an empty body, a
        /// body that is not a JSON object, or an object without <c>meta</c>) does not throw — Snyk may already have
        /// deleted the batch — and its ids are reported in <see cref="SnykBulkDeleteResult.Unreported"/>.
        /// An empty <paramref name="projectIds"/> makes no request.
        /// </summary>
        public async Task<SnykBulkDeleteResult> BulkDeleteAsync(
            string orgId,
            IReadOnlyCollection<string> projectIds,
            CancellationToken cancellationToken = default)
        {
            var deleted = new List<SnykBulkDeletedProject>();
            var failed = new List<SnykBulkDeleteFailure>();
            var unreported = new List<string>();

            if (projectIds.Count == 0)
            {
                return new SnykBulkDeleteResult { Deleted = deleted, Failed = failed, Unreported = unreported };
            }

            var url = _transport.BuildUrl($"/orgs/{Uri.EscapeDataString(orgId)}/projects/bulk-delete");

            foreach (var batch in projectIds.Chunk(BulkDeleteBatchSize))
            {
                var data = new JsonArray();
                foreach (var id in batch)
                {
                    data.Add(new JsonObject { ["type"] = "project", ["id"] = id });
                }

                var body = new JsonObject { ["data"] = data }.ToJsonString();

                using var doc = await PostBulkDeleteBatchAsync(url, body, cancellationToken);
                if (doc is null
                    || doc.RootElement.ValueKind != JsonValueKind.Object
                    || !doc.RootElement.TryGetProperty("meta", out var meta)
                    || meta.ValueKind != JsonValueKind.Object)
                {
                    // The endpoint's success schema requires a meta summary; without it there is no way to tell
                    // which projects were deleted. Throwing would hide that Snyk may already have deleted them, so
                    // the batch is reported as unconfirmed for the caller to verify.
                    unreported.AddRange(batch);
                    continue;
                }

                // An entry without an id cannot be matched to a requested project, so it is skipped; callers that
                // need every project accounted for should compare the ids they sent against both lists.
                if (meta.TryGetProperty("deleted", out var deletedArray) && deletedArray.ValueKind == JsonValueKind.Array)
                {
                    foreach (var item in deletedArray.EnumerateArray())
                    {
                        if (JsonReader.Str(item, "id") is { Length: > 0 } id)
                        {
                            deleted.Add(new SnykBulkDeletedProject { Id = id, Name = JsonReader.Str(item, "name") });
                        }
                    }
                }

                if (meta.TryGetProperty("failed", out var failedArray) && failedArray.ValueKind == JsonValueKind.Array)
                {
                    foreach (var item in failedArray.EnumerateArray())
                    {
                        if (JsonReader.Str(item, "id") is { Length: > 0 } id)
                        {
                            failed.Add(new SnykBulkDeleteFailure
                            {
                                Id = id,
                                Name = JsonReader.Str(item, "name"),
                                Reason = JsonReader.Str(item, "reason"),
                            });
                        }
                    }
                }
            }

            return new SnykBulkDeleteResult { Deleted = deleted, Failed = failed, Unreported = unreported };
        }

        /// <summary>
        /// Posts one bulk-delete batch. Returns null when the success response has no parseable JSON body; a
        /// non-2xx still throws <see cref="SnykApiException"/>.
        /// </summary>
        private async Task<JsonDocument?> PostBulkDeleteBatchAsync(string url, string body, CancellationToken cancellationToken)
        {
            try
            {
                return await _transport.PostOrEmptyAsync(url, body, cancellationToken);
            }
            catch (JsonException)
            {
                // Only a success response's body is parsed, so this is a 2xx whose outcome cannot be read.
                return null;
            }
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

        /// <summary>Deletes a target. Idempotent: a missing target is treated as already deleted. Throws
        /// <see cref="SnykApiException"/> on a non-404 API failure so the caller can retry.</summary>
        public Task DeleteAsync(string orgId, string targetId, CancellationToken cancellationToken = default)
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
