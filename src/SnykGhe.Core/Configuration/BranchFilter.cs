using System.IO.Enumeration;

namespace SnykGhe.Core.Configuration
{
    /// <summary>
    /// Decides whether a pull request should be scanned based on its <em>base</em> (target) branch — the
    /// branch the PR merges into, e.g. <c>main</c> for a <c>feature → main</c> PR. A scan-target policy is a
    /// list of glob patterns matched against that base ref; an <em>empty</em> list means "scan every PR" (the
    /// out-of-box default, so filtering is purely opt-in).
    ///
    /// Patterns support <c>*</c> / <c>?</c> wildcards (so <c>release/*</c> matches <c>release/2.0</c>) and one
    /// special token, <c>$default</c>, which matches the repository's default branch — letting a policy target
    /// "the default branch" without hard-coding its name (it is not always <c>main</c>). Use <c>*</c> to match
    /// every branch explicitly, e.g. to opt a repo back into scanning under a restrictive org policy.
    /// Matching is case-insensitive.
    /// </summary>
    public static class BranchFilter
    {
        private const char Delimiter = '\n';

        /// <summary>The token that expands to the repository's default branch at match time.</summary>
        public const string DefaultBranchToken = "$default";

        /// <summary>
        /// Trims each pattern, drops blanks, and de-duplicates (case-insensitively) while preserving order.
        /// </summary>
        public static IReadOnlyList<string> Sanitize(IEnumerable<string>? patterns)
        {
            if (patterns is null)
            {
                return [];
            }

            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var result = new List<string>();

            foreach (var raw in patterns)
            {
                if (string.IsNullOrWhiteSpace(raw))
                {
                    continue;
                }

                var trimmed = raw.Trim();
                if (seen.Add(trimmed))
                {
                    result.Add(trimmed);
                }
            }

            return result;
        }

        /// <summary>Serializes the list to a single storage column, or null when empty (so the column is cleared).</summary>
        public static string? Join(IReadOnlyList<string>? patterns) =>
            patterns is { Count: > 0 } ? string.Join(Delimiter, patterns) : null;

        /// <summary>Parses a stored column back into a list.</summary>
        public static IReadOnlyList<string> Split(string? stored) =>
            string.IsNullOrEmpty(stored)
                ? []
                : stored.Split(Delimiter, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        /// <summary>
        /// Returns true when a PR whose base branch is <paramref name="baseRef"/> should be scanned under the
        /// given <paramref name="patterns"/>. An empty pattern list matches everything (scan all). A null or
        /// blank <paramref name="baseRef"/> also matches (fail open — never suppress a scan because the base
        /// branch could not be determined). <paramref name="defaultBranch"/> resolves the <c>$default</c> token
        /// and may be null when it is unknown.
        /// </summary>
        public static bool Matches(IReadOnlyList<string> patterns, string? baseRef, string? defaultBranch)
        {
            if (patterns.Count == 0 || string.IsNullOrWhiteSpace(baseRef))
            {
                return true;
            }

            foreach (var pattern in patterns)
            {
                if (string.Equals(pattern, DefaultBranchToken, StringComparison.OrdinalIgnoreCase))
                {
                    if (!string.IsNullOrWhiteSpace(defaultBranch) &&
                        string.Equals(baseRef, defaultBranch, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }

                    continue;
                }

                // Simple-expression globbing: only '*' and '?' are special; '/' is a literal, so 'release/*'
                // matches 'release/2.0'. Case-insensitive to match how branch names are usually written.
                if (FileSystemName.MatchesSimpleExpression(pattern, baseRef, ignoreCase: true))
                {
                    return true;
                }
            }

            return false;
        }
    }
}
