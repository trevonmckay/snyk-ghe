using Octokit.Webhooks;
using SnykGhe.WebhookService.Configuration;
using SnykGhe.WebhookService.Fix;
using SnykGhe.WebhookService.GitHub;
using SnykGhe.WebhookService.Processing;
using SnykGhe.WebhookService.Snyk;
using SnykGhe.WebhookService.Storage;
using SnykGhe.WebhookService.Webhooks;

var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddOptions<GitHubOptions>()
    .Bind(builder.Configuration.GetSection(GitHubOptions.SectionName));

builder.Services
    .AddOptions<SnykOptions>()
    .Bind(builder.Configuration.GetSection(SnykOptions.SectionName));

builder.Services
    .AddOptions<StorageOptions>()
    .Bind(builder.Configuration.GetSection(StorageOptions.SectionName));

var storageProvider = builder.Configuration
    .GetSection(StorageOptions.SectionName)
    .GetValue<StorageProvider>(nameof(StorageOptions.Provider));

if (storageProvider == StorageProvider.DynamoDb)
{
    builder.Services.AddSingleton<IGitHubInstallationRegistry, DynamoDbGitHubInstallationRegistry>();
}
else
{
    builder.Services.AddSingleton<IGitHubInstallationRegistry, TableStorageGitHubInstallationRegistry>();
}

builder.Services.AddHostedService<GitHubInstallationRegistryInitializer>();
builder.Services.AddSingleton<GitHubClientFactory>();
builder.Services.AddSingleton<OrgPolicyResolver>();
builder.Services.AddSingleton<SnykScanner>();
builder.Services.AddSingleton<FixPlanner>();
builder.Services.AddSingleton<IManifestPatcher, NuGetManifestPatcher>();
builder.Services.AddSingleton<FixPullRequestService>();
builder.Services.AddSingleton<IScanQueue, ChannelScanQueue>();
builder.Services.AddSingleton<PullRequestCheckService>();
builder.Services.AddHostedService<ScanWorker>();
builder.Services.AddSingleton<WebhookEventProcessor, GitHubWebhookEventProcessor>();

builder.Services.AddControllers();

var app = builder.Build();

app.MapControllers();

app.Run();
