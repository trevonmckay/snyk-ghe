namespace SnykGhe.Core.Configuration
{
    /// <summary>
    /// Normalizes the Snyk <c>--exclude</c> list. The flag accepts directory/file <em>names</em>, never
    /// paths: a value containing a path separator errors the CLI and fails the entire <c>--all-projects</c>
    /// scan, so a path-like entry is rejected at the admin write (400) and defensively dropped here on the way
    /// out, degrading a misconfiguration to "ignored" rather than "scan broken".
    /// </summary>
    public static class ExcludeList
    {
        private const char Delimiter = '\n';

        /// <summary>A value that would be interpreted as a path (and so break the scan) rather than a name.</summary>
        public static bool IsPathLike(string entry) =>
            entry.Contains('/') || entry.Contains('\\');

        /// <summary>
        /// Trims each entry, drops blanks and path-like entries, and de-duplicates while preserving order.
        /// Comparison is case-sensitive: an exclude entry matches a directory/file name literally.
        /// </summary>
        public static IReadOnlyList<string> Sanitize(IEnumerable<string>? entries)
        {
            if (entries is null)
            {
                return [];
            }

            var seen = new HashSet<string>(StringComparer.Ordinal);
            var result = new List<string>();

            foreach (var raw in entries)
            {
                if (string.IsNullOrWhiteSpace(raw))
                {
                    continue;
                }

                var trimmed = raw.Trim();
                if (IsPathLike(trimmed))
                {
                    continue;
                }

                if (seen.Add(trimmed))
                {
                    result.Add(trimmed);
                }
            }

            return result;
        }

        /// <summary>Serializes the list to a single storage column, or null when empty (so the column is cleared).</summary>
        public static string? Join(IReadOnlyList<string>? entries) =>
            entries is { Count: > 0 } ? string.Join(Delimiter, entries) : null;

        /// <summary>Parses a stored column back into a list.</summary>
        public static IReadOnlyList<string> Split(string? stored) =>
            string.IsNullOrEmpty(stored)
                ? []
                : stored.Split(Delimiter, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }
}
