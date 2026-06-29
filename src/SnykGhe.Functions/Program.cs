using Azure.Identity;
using Azure.Messaging.ServiceBus;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SnykGhe.Functions;

var host = new HostBuilder()
    .ConfigureFunctionsWorkerDefaults()
    .ConfigureServices((context, services) =>
    {
        services.AddApplicationInsightsTelemetryWorkerService();
        services.ConfigureFunctionsApplicationInsights();

        services.Configure<FunctionOptions>(options =>
        {
            options.WebhookSecret = context.Configuration["GitHubWebhookSecret"] ?? string.Empty;
        });

        // The isolated-worker Service Bus *output binding* cannot carry a ServiceBusMessage: the runtime
        // JSON-serializes the object, which drops the ApplicationProperties (the X-GitHub-Event routing
        // header) and mangles the raw body, so the consumer dead-letters every delivery. Send via a
        // ServiceBusSender directly instead. Authentication is the user-assigned managed identity.
        //
        // The connection details are stored as the identity-based binding's app settings
        // (ServiceBusConnection__fullyQualifiedNamespace / __clientId). Configuration normalizes the
        // "__" separator to ":", so they must be read with a colon, not the literal double underscore.
        var fullyQualifiedNamespace = context.Configuration["ServiceBusConnection:fullyQualifiedNamespace"]
            ?? throw new InvalidOperationException("ServiceBusConnection:fullyQualifiedNamespace is not configured.");
        var queueName = context.Configuration["ServiceBusQueueName"]
            ?? throw new InvalidOperationException("ServiceBusQueueName is not configured.");
        var managedIdentityClientId = context.Configuration["ServiceBusConnection:clientId"];

        services.AddSingleton(_ => new ServiceBusClient(
            fullyQualifiedNamespace,
            new DefaultAzureCredential(new DefaultAzureCredentialOptions
            {
                ManagedIdentityClientId = managedIdentityClientId,
            })));
        services.AddSingleton(sp => sp.GetRequiredService<ServiceBusClient>().CreateSender(queueName));
    })
    .Build();

host.Run();
