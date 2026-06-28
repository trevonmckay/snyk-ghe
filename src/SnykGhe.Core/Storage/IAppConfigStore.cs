namespace SnykGhe.Core.Storage
{
    /// <summary>
    /// Persists non-secret, app-level configuration in the same backing store as the installation
    /// registry. Used by the registration flow to record the generated (public) GitHub App ID so the
    /// service can load it on startup without an operator setting it by hand.
    /// </summary>
    public interface IAppConfigStore
    {
        Task<string?> GetAppIdAsync(CancellationToken cancellationToken = default);

        Task SetAppIdAsync(string appId, CancellationToken cancellationToken = default);
    }
}
