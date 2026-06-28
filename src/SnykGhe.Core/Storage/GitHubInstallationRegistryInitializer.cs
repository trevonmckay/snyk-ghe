namespace SnykGhe.Core.Storage
{
    /// <summary>Creates the installation table at startup so request paths never pay for it.</summary>
    public sealed class GitHubInstallationRegistryInitializer : IHostedService
    {
        private readonly IGitHubInstallationRegistry _registry;

        public GitHubInstallationRegistryInitializer(IGitHubInstallationRegistry registry)
        {
            _registry = registry;
        }

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            await _registry.EnsureCreatedAsync(cancellationToken);
        }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }
    }
}
