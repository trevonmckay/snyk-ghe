using Microsoft.Azure.Functions.Worker;
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
    })
    .Build();

host.Run();
