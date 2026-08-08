using Amazon.SecretsManager;
using Amazon.SQS;
using Azure.Extensions.AspNetCore.Configuration.Secrets;
using Azure.Identity;
using Azure.Messaging.ServiceBus;
using Microsoft.ApplicationInsights.Extensibility;
using Microsoft.Extensions.Options;
using Octokit.Webhooks;
using SnykGhe.Core.Configuration;
using SnykGhe.Service;
using SnykGhe.Service.Authentication;
using SnykGhe.Service.Configuration;
using SnykGhe.Core.Fix;
using SnykGhe.Core.GitHub;
using SnykGhe.Core.GitHub.Manifest;
using SnykGhe.Core.Messaging;
using SnykGhe.Core.Processing;
using SnykGhe.Core.Secrets;
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

builder.Services
    .AddOptions<RegistrationOptions>()
    .Bind(builder.Configuration.GetSection(RegistrationOptions.SectionName));

builder.Services
    .AddOptions<SecretRepositoryOptions>()
    .Bind(builder.Configuration.GetSection(SecretRepositoryOptions.SectionName));

builder.Services
    .AddOptions<AuthOptions>()
    .Bind(builder.Configuration.GetSection(AuthOptions.SectionName))
    .ValidateOnStart();
builder.Services.AddSingleton<IValidateOptions<AuthOptions>, AuthOptionsValidator>();

var storageProvider = builder.Configuration
    .GetSection(StorageOptions.SectionName)
    .GetValue<StorageProvider>(nameof(StorageOptions.Provider));

if (storageProvider == StorageProvider.DynamoDb)
{
    builder.Services.AddSingleton<IGitHubInstallationRegistry, DynamoDbGitHubInstallationRegistry>();
    builder.Services.AddSingleton<IAppConfigStore, DynamoDbAppConfigStore>();
    builder.Services.AddSingleton<IScanCoordinationStore, DynamoDbScanCoordinationStore>();
}
else
{
    builder.Services.AddSingleton<IGitHubInstallationRegistry, TableStorageGitHubInstallationRegistry>();
    builder.Services.AddSingleton<IAppConfigStore, TableAppConfigStore>();
    builder.Services.AddSingleton<IScanCoordinationStore, TableStorageScanCoordinationStore>();
}

builder.Services.AddHostedService<GitHubInstallationRegistryInitializer>();
builder.Services.AddSingleton<GitHubClientFactory>();
builder.Services.AddSingleton<OrgPolicyResolver>();
builder.Services.AddSnykScanning(builder.Configuration);
builder.Services.AddSingleton<FixPlanner>();
builder.Services.AddSingleton<IManifestPatcher, NuGetManifestPatcher>();
builder.Services.AddSingleton<FixPullRequestService>();
builder.Services.AddSingleton<RepositoryCloner>();
builder.Services.AddHttpClient(CodeScanningSarifUploader.HttpClientName);
builder.Services.AddSingleton<CodeScanningSarifUploader>();
builder.Services.AddSingleton<PullRequestCheckService>();
builder.Services.AddSingleton<ScanCoalescer>();
builder.Services.AddSingleton<BaselineScanService>();
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

// On SIGTERM (replica scale-in or a new revision) let an in-flight scan finish before the host
// forces shutdown. The queue worker's StopAsync stops accepting new messages and drains what's
// running; this window has to be long enough for that drain and must stay below the platform's
// termination grace period (the Container App's terminationGracePeriodSeconds on Azure) so the drain
// completes before SIGKILL. Deploy-tunable so each host can match its own grace period.
var shutdownTimeoutSeconds = builder.Configuration.GetValue("Host:ShutdownTimeoutSeconds", 240);
builder.Services.Configure<HostOptions>(options =>
{
    options.ShutdownTimeout = TimeSpan.FromSeconds(shutdownTimeoutSeconds);
});

// Self-service App registration (manifest flow) + post-install setup page.
builder.Services.AddHttpClient<GitHubAppManifestService>();
builder.Services.AddSingleton<RegistrationStateProtector>();

var secretsOptions = builder.Configuration
    .GetSection(SecretRepositoryOptions.SectionName)
    .Get<SecretRepositoryOptions>();

var secretStoreProvider = secretsOptions?.Provider ?? SecretStoreProvider.None;
var secretsAwsRegion = secretsOptions?.AwsRegion;

// The GitHub App private key and webhook secret are generated by the registration flow and written to Key
// Vault — never seeded by the deploy template. Load them from Key Vault at runtime (mapped onto GitHub:*
// config keys) so a fresh deploy needs no placeholder secrets and infra redeploys cannot clobber the
// registration-written values. Picked up on the next app start (restart after registering).
if (secretStoreProvider == SecretStoreProvider.AzureKeyVault && !string.IsNullOrWhiteSpace(secretsOptions?.KeyVaultUri))
{
    builder.Configuration.AddAzureKeyVault(
        new Uri(secretsOptions.KeyVaultUri),
        new DefaultAzureCredential(),
        new AzureKeyVaultConfigurationOptions
        {
            Manager = new GitHubCredentialSecretManager(
                secretsOptions.PrivateKeySecretName,
                secretsOptions.WebhookSecretName),
        });
}

switch (secretStoreProvider)
{
    case SecretStoreProvider.AzureKeyVault:
        builder.Services.AddSingleton<IAppCredentialStore, KeyVaultAppCredentialStore>();
        break;
    case SecretStoreProvider.AwsSecretsManager:
        builder.Services.AddSingleton<IAmazonSecretsManager>(_ =>
            string.IsNullOrWhiteSpace(secretsAwsRegion)
                ? new AmazonSecretsManagerClient()
                : new AmazonSecretsManagerClient(Amazon.RegionEndpoint.GetBySystemName(secretsAwsRegion)));
        builder.Services.AddSingleton<IAppCredentialStore, SecretsManagerAppCredentialStore>();
        break;
    default:
        builder.Services.AddSingleton<IAppCredentialStore, DisplayOnceAppCredentialStore>();
        break;
}

// Application Insights for the processing tier. Enabled only when a connection string is configured, so
// local runs and non-Azure hosts stay quiet. Ingestion authenticates with the ambient managed identity
// rather than an embedded instrumentation key, matching how the app reaches its other Azure resources.
if (!string.IsNullOrWhiteSpace(builder.Configuration["APPLICATIONINSIGHTS_CONNECTION_STRING"]))
{
    builder.Services.AddApplicationInsightsTelemetry();
    builder.Services.Configure<TelemetryConfiguration>(
        config => config.SetAzureTokenCredential(new DefaultAzureCredential()));

    // A Container App sets no WEBSITE_SITE_NAME, so the built-in role-name initializers leave
    // cloud_RoleName empty; supply it explicitly when configured so this tier is named in App Insights.
    var roleName = builder.Configuration["APPLICATIONINSIGHTS_ROLE_NAME"];
    if (!string.IsNullOrWhiteSpace(roleName))
    {
        builder.Services.AddSingleton<ITelemetryInitializer>(new RoleNameTelemetryInitializer(roleName));
    }
}

// Admin API authentication. Which schemes are registered is driven by Auth:Methods; the AuthOptions
// validator (ValidateOnStart) has already guaranteed the enabled methods carry their required settings, so
// a fresh deploy fails loudly rather than exposing or locking out the admin surface. Any enabled scheme can
// satisfy the AdminAccess policy — admin key or OAuth2 bearer — which is how both run side by side.
var authOptions = builder.Configuration
    .GetSection(AuthOptions.SectionName)
    .Get<AuthOptions>() ?? new AuthOptions();

var authenticationBuilder = builder.Services.AddAuthentication();
var enabledSchemes = new List<string>();

if (authOptions.AdminKeyEnabled)
{
    authenticationBuilder.AddScheme<AdminKeyAuthenticationOptions, AdminKeyAuthenticationHandler>(
        AdminKeyAuthenticationHandler.SchemeName, _ => { });
    enabledSchemes.Add(AdminKeyAuthenticationHandler.SchemeName);
}

if (authOptions.OAuth2Enabled)
{
    authenticationBuilder.AddJwtBearer(AuthOptions.OAuth2Method, options =>
    {
        options.Authority = authOptions.OAuth2.Authority;
        options.Audience = authOptions.OAuth2.Audience;
        options.RequireHttpsMetadata = authOptions.OAuth2.RequireHttpsMetadata;

        // Keep the original JWT claim names (scp/roles/groups/...) instead of remapping them to the long
        // WS-* URIs, so the configured Auth:OAuth2:ScopeClaimTypes / RoleClaimTypes match what IdPs emit.
        options.MapInboundClaims = false;
    });
    enabledSchemes.Add(AuthOptions.OAuth2Method);
}

// No method enabled: leave the admin API closed (every request rejected) rather than failing startup —
// a deployment that configures everything via app config may never call the admin endpoints. The closed
// scheme gives the AdminAccess policy a scheme to challenge, so those endpoints return a clean 401.
if (enabledSchemes.Count == 0)
{
    authenticationBuilder.AddScheme<AdminClosedAuthenticationOptions, AdminClosedAuthenticationHandler>(
        AdminClosedAuthenticationHandler.SchemeName, _ => { });
    enabledSchemes.Add(AdminClosedAuthenticationHandler.SchemeName);
}

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy(AdminAuthorization.PolicyName, policy =>
    {
        policy.AddAuthenticationSchemes([.. enabledSchemes]);
        policy.RequireAuthenticatedUser();
        policy.RequireAssertion(context => AdminAuthorization.IsAuthorized(context, authOptions.OAuth2));
    });
});

builder.Services.AddControllers();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
