using System.Text.Json;
using System.Text.Json.Nodes;
using SnykGhe.Core.Configuration;

namespace SnykGhe.Core.Snyk
{
    /// <summary>One dependency graph produced from a working copy, with the manifest it came from.</summary>
    public sealed class DepGraphDocument
    {
        public required string Name { get; init; }

        public required JsonNode Graph { get; init; }
    }

    /// <summary>
    /// Outcome of generating dependency graphs. <see cref="Failed"/> must be distinguished from an empty
    /// <see cref="Graphs"/>: a repository with no manifests legitimately yields no graphs, whereas a CLI
    /// that could not authenticate also yields none. Treating the two alike would report a clean scan for a
    /// repository that was never scanned.
    /// </summary>
    public sealed class DepGraphResult
    {
        public IReadOnlyList<DepGraphDocument> Graphs { get; init; } = [];

        public bool Failed { get; init; }

        public string? FailureMessage { get; init; }

        public static DepGraphResult Success(IReadOnlyList<DepGraphDocument> graphs) => new() { Graphs = graphs };

        public static DepGraphResult Failure(string message) => new() { Failed = true, FailureMessage = message };
    }

    /// <summary>
    /// Produces Snyk dependency graphs for a working copy.
    ///
    /// The Test API's only SCA input that requires nothing to be pre-registered with Snyk is an inline
    /// dependency graph, and the sole supported way to build one for every ecosystem Snyk understands is the
    /// CLI's <c>--print-graph</c>. That flag is absent from <c>snyk test --help</c> and is not covered by
    /// Snyk's compatibility guarantees, so every assumption about it is confined to this class: it emits one
    /// <c>DepGraph data:</c> banner per project, each followed by a graph document.
    /// </summary>
    public sealed class DepGraphGenerator
    {
        private const string GraphBanner = "DepGraph data:";

        // The CLI interleaves a trailing "DepGraph target:" line naming the manifest each graph came from.
        private const string TargetBanner = "DepGraph target:";

        private readonly SnykCliRunner _cli;
        private readonly ILogger<DepGraphGenerator> _logger;

        public DepGraphGenerator(SnykCliRunner cli, ILogger<DepGraphGenerator> logger)
        {
            _cli = cli;
            _logger = logger;
        }

        /// <summary>Builds a dependency graph per project in the working copy.</summary>
        public async Task<DepGraphResult> GenerateAsync(ScanContext context, CancellationToken cancellationToken)
        {
            await _cli.RestoreDependenciesAsync(context.WorkingDirectory, context.Policy.Ecosystem, cancellationToken);

            var args = new List<string> { "test", "--print-graph", "--all-projects" };
            SnykCliRunner.AddNuGetNamingArgs(args, context.Policy);
            SnykCliRunner.AddOrgArg(args, context.Policy);
            SnykCliRunner.AddExcludeArgs(args, context.Policy);

            var outcome = await _cli.RunAsync(args, context.WorkingDirectory, cancellationToken);
            var result = FromOutcome(outcome);

            if (result.Failed)
            {
                _logger.LogWarning("Snyk CLI could not print dependency graphs in {Dir}: {Message}",
                    context.WorkingDirectory, result.FailureMessage);
            }

            return result;
        }

        /// <summary>
        /// Classifies a CLI invocation. Exit codes match <c>snyk test</c>: 0 = clean, 1 = vulnerabilities found
        /// (the graphs are still printed), 2 = CLI/usage error, 3 = no supported manifests. Anything at or above
        /// 2 is a failure, mirroring the CLI Open Source scanner, so the two engines agree on what a scan that
        /// could not run looks like.
        /// </summary>
        internal static DepGraphResult FromOutcome(SnykCliOutcome outcome)
        {
            if (outcome.AuthenticationFailed)
            {
                return DepGraphResult.Failure("Snyk OAuth authentication failed.");
            }

            if (outcome.TimedOut)
            {
                return DepGraphResult.Failure("Snyk dependency-graph generation timed out.");
            }

            if (outcome.ExitCode >= 2)
            {
                var detail = outcome.Detail;
                return DepGraphResult.Failure(string.IsNullOrWhiteSpace(detail)
                    ? $"Snyk CLI exited with code {outcome.ExitCode} while printing dependency graphs."
                    : detail.Trim());
            }

            return DepGraphResult.Success(Parse(outcome.StandardOutput));
        }

        /// <summary>
        /// Extracts each graph document that follows a <c>DepGraph data:</c> banner. The CLI mixes these with
        /// human-readable text, so each JSON object is scanned by brace depth rather than by line.
        /// </summary>
        internal static IReadOnlyList<DepGraphDocument> Parse(string output)
        {
            var documents = new List<DepGraphDocument>();

            if (string.IsNullOrWhiteSpace(output))
            {
                return documents;
            }

            var index = 0;
            var ordinal = 0;

            while (true)
            {
                var banner = output.IndexOf(GraphBanner, index, StringComparison.Ordinal);
                if (banner < 0)
                {
                    break;
                }

                var start = output.IndexOf('{', banner + GraphBanner.Length);
                if (start < 0)
                {
                    break;
                }

                var end = FindObjectEnd(output, start);
                if (end < 0)
                {
                    break;
                }

                var json = output[start..(end + 1)];
                index = end + 1;

                JsonNode? graph;
                try
                {
                    graph = JsonNode.Parse(json);
                }
                catch (JsonException)
                {
                    continue;
                }

                if (graph is null)
                {
                    continue;
                }

                documents.Add(new DepGraphDocument
                {
                    Name = ReadTargetName(output, index) ?? $"dep-graph-{++ordinal}.json",
                    Graph = graph,
                });
            }

            return documents;
        }

        /// <summary>
        /// Reads the manifest path a graph came from. The CLI prints it on the line after the
        /// <c>DepGraph target:</c> banner, e.g. <c>src\Foo\obj\project.assets.json</c>.
        /// </summary>
        private static string? ReadTargetName(string output, int from)
        {
            var banner = output.IndexOf(TargetBanner, from, StringComparison.Ordinal);
            if (banner < 0)
            {
                return null;
            }

            // Only accept a target banner that belongs to the graph just read, not a later one.
            var nextGraph = output.IndexOf(GraphBanner, from, StringComparison.Ordinal);
            if (nextGraph >= 0 && banner > nextGraph)
            {
                return null;
            }

            var rest = output[(banner + TargetBanner.Length)..];
            foreach (var line in rest.Split('\n'))
            {
                var trimmed = line.Trim();
                if (trimmed.Length == 0)
                {
                    continue;
                }

                return trimmed.Equals("DepGraph end", StringComparison.Ordinal) ? null : trimmed;
            }

            return null;
        }

        /// <summary>Returns the index of the brace closing the object that opens at <paramref name="start"/>.</summary>
        private static int FindObjectEnd(string text, int start)
        {
            var depth = 0;
            var inString = false;
            var escaped = false;

            for (var i = start; i < text.Length; i++)
            {
                var c = text[i];

                if (escaped)
                {
                    escaped = false;
                    continue;
                }

                if (inString)
                {
                    if (c == '\\')
                    {
                        escaped = true;
                    }
                    else if (c == '"')
                    {
                        inString = false;
                    }

                    continue;
                }

                switch (c)
                {
                    case '"':
                        inString = true;
                        break;
                    case '{':
                        depth++;
                        break;
                    case '}':
                        depth--;
                        if (depth == 0)
                        {
                            return i;
                        }

                        break;
                }
            }

            return -1;
        }
    }
}
