namespace SnykGhe.Core.Secrets
{
    /// <summary>
    /// Fallback store used when no secret store is configured: it does not persist anything, signalling the
    /// controller to render the credentials once for the operator to copy. For local/dev only.
    /// </summary>
    public sealed class DisplayOnceAppCredentialStore : IAppCredentialStore
    {
        public bool PersistsSecrets => false;

        public string Describe() => "not persisted (no secret store configured)";

        public Task WriteAsync(AppCredentials credentials, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
    }
}
