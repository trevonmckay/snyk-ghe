namespace SnykGhe.Core.Storage
{
    /// <summary>Creates the installation and scan-coordination tables at startup so request paths never pay for it.</summary>
    public sealed class GitHubInstallationRegistryInitializer : IHostedService
    {
        private readonly IGitHubInstallationRegistry _registry;
        private readonly IScanCoordinationStore _scanCoordination;

        public GitHubInstallationRegistryInitializer(IGitHubInstallationRegistry registry, IScanCoordinationStore scanCoordination)
        {
            _registry = registry;
            _scanCoordination = scanCoordination;
        }

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            await _registry.EnsureCreatedAsync(cancellationToken);
            await _scanCoordination.EnsureCreatedAsync(cancellationToken);
        }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }
    }
}
