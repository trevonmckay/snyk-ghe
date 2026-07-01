using CliWrap;
using CliWrap.Buffered;

namespace SnykGhe.Core.Processing
{
    /// <summary>
    /// Shallow-clones a single branch of a repository over HTTPS, authenticating as a GitHub App
    /// installation. Shared by the pull-request and default-branch scan pipelines.
    /// </summary>
    public sealed class RepositoryCloner
    {
        /// <summary>
        /// Clones <paramref name="branch"/> of <paramref name="cloneUrl"/> into <paramref name="workDir"/>.
        /// Throws <see cref="InvalidOperationException"/> when git exits non-zero.
        /// </summary>
        public async Task CloneAsync(
            string cloneUrl,
            string branch,
            string token,
            string workDir,
            CancellationToken cancellationToken)
        {
            // GitHub App installation tokens authenticate git over HTTPS as x-access-token.
            var authUrl = cloneUrl.Replace("https://", $"https://x-access-token:{token}@", StringComparison.Ordinal);

            var result = await Cli.Wrap("git")
                .WithArguments(["clone", "--depth", "1", "--branch", branch, authUrl, workDir])
                .WithValidation(CommandResultValidation.None)
                .ExecuteBufferedAsync(cancellationToken);

            if (result.ExitCode != 0)
            {
                throw new InvalidOperationException($"git clone failed (exit {result.ExitCode}): {result.StandardError.Trim()}");
            }
        }
    }
}
