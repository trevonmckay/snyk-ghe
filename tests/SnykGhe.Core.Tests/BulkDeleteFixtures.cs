using System.Text.Json;

namespace SnykGhe.Core.Tests
{
    /// <summary>Builds Snyk bulk-delete responses and reads bulk-delete requests for stub HTTP handlers.</summary>
    internal static class BulkDeleteFixtures
    {
        /// <summary>
        /// A <c>200</c> bulk-delete body reporting <paramref name="deleted"/> in <c>meta.deleted</c> and
        /// <paramref name="failed"/> in <c>meta.failed</c>. An id in neither list mirrors Snyk ignoring a
        /// project it does not find.
        /// </summary>
        internal static string Summary(IEnumerable<string>? deleted = null, IEnumerable<(string Id, string Reason)>? failed = null)
        {
            var deletedJson = string.Join(",", (deleted ?? []).Select(id => $"{{\"id\":\"{id}\",\"name\":\"n-{id}\"}}"));
            var failedJson = string.Join(",", (failed ?? []).Select(f => $"{{\"id\":\"{f.Id}\",\"name\":\"n-{f.Id}\",\"reason\":\"{f.Reason}\"}}"));
            return $"{{\"jsonapi\":{{\"version\":\"1.0\"}},\"meta\":{{\"deleted\":[{deletedJson}],\"failed\":[{failedJson}]}}}}";
        }

        /// <summary>The project ids (<c>data[].id</c>) in a bulk-delete request body.</summary>
        internal static IReadOnlyList<string> RequestedIds(string body)
        {
            using var doc = JsonDocument.Parse(body);
            return doc.RootElement.GetProperty("data").EnumerateArray()
                .Select(item => item.GetProperty("id").GetString()!)
                .ToList();
        }

        /// <summary>Reads a bulk-delete request and returns the project ids it names.</summary>
        internal static async Task<IReadOnlyList<string>> RequestedIds(HttpRequestMessage request, CancellationToken cancellationToken) =>
            RequestedIds(await request.Content!.ReadAsStringAsync(cancellationToken));
    }
}
