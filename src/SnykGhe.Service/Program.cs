using Amazon.SQS;
using Azure.Identity;
using Azure.Messaging.ServiceBus;
using Octokit.Webhooks;
using SnykGhe.Core.Configuration;
using SnykGhe.Core.Fix;
using SnykGhe.Core.GitHub;
using SnykGhe.Core.Messaging;
using SnykGhe.Core.Processing;
using SnykGhe.Core.Snyk;
using SnykGhe.Core.Storage;
using SnykGhe.Core.Webhooks;

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

builder.Services
    .AddOptions<ServiceBusOptions>()
    .Bind(builder.Configuration.GetSection(ServiceBusOptions.SectionName));

builder.Services
    .AddOptions<SqsOptions>()
    .Bind(builder.Configuration.GetSection(SqsOptions.SectionName));

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
builder.Services.AddSingleton<PullRequestCheckService>();
builder.Services.AddSingleton<WebhookEventProcessor, GitHubWebhookEventProcessor>();
builder.Services.AddSingleton<WebhookDispatcher>();

// Durable webhook queue: Service Bus on Azure, SQS on AWS; in-process channel otherwise (local dev).
var serviceBusOptions = builder.Configuration
    .GetSection(ServiceBusOptions.SectionName)
    .Get<ServiceBusOptions>();

var sqsOptions = builder.Configuration
    .GetSection(SqsOptions.SectionName)
    .Get<SqsOptions>();

if (serviceBusOptions?.IsConfigured == true)
{
    builder.Services.AddSingleton(_ => new ServiceBusClient(
        serviceBusOptions.FullyQualifiedNamespace,
        new DefaultAzureCredential()));
    builder.Services.AddSingleton<IWebhookQueue, ServiceBusWebhookQueue>();
    builder.Services.AddHostedService<ServiceBusWebhookWorker>();
}
else if (sqsOptions?.IsConfigured == true)
{
    builder.Services.AddSingleton<IAmazonSQS>(_ =>
        string.IsNullOrWhiteSpace(sqsOptions.AwsRegion)
            ? new AmazonSQSClient()
            : new AmazonSQSClient(Amazon.RegionEndpoint.GetBySystemName(sqsOptions.AwsRegion)));
    builder.Services.AddSingleton<IWebhookQueue, SqsWebhookQueue>();
    builder.Services.AddHostedService<SqsWebhookWorker>();
}
else
{
    builder.Services.AddSingleton<ChannelWebhookQueue>();
    builder.Services.AddSingleton<IWebhookQueue>(sp => sp.GetRequiredService<ChannelWebhookQueue>());
    builder.Services.AddHostedService<ChannelWebhookWorker>();
}

builder.Services.AddControllers();

var app = builder.Build();

app.MapControllers();

app.Run();
