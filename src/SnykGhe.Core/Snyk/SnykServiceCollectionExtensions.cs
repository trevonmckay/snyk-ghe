using Snyk.Client;
using SnykGhe.Core.Configuration;

namespace SnykGhe.Core.Snyk
{
    public static class SnykServiceCollectionExtensions
    {
        /// <summary>
        /// Registers the Snyk credential providers, REST client, and one implementation per scanner chosen by
        /// <see cref="SnykOptions.Engines"/>. An engine combination Snyk cannot serve is rejected here rather
        /// than failing every scan at run time.
        /// </summary>
        public static IServiceCollection AddSnykScanning(this IServiceCollection services, IConfiguration configuration)
        {
            var snyk = configuration.GetSection(SnykOptions.SectionName).Get<SnykOptions>() ?? new SnykOptions();
            ValidateApiVersion(snyk);
            ValidateEngines(snyk);

            services.AddHttpClient(SnykOAuthTokenProvider.HttpClientName);
            services.AddSingleton<SnykOAuthTokenProvider>();
            services.AddSingleton<ISnykTokenProvider, SnykApiTokenProvider>();

            services.Configure<SnykApiOptions>(options =>
            {
                options.BaseUrl = snyk.ApiBaseUrl;
                options.ApiVersion = snyk.RestApiVersion;
                options.TestTimeout = TimeSpan.FromSeconds(snyk.ScanTimeoutSeconds);
            });
            services.AddSnykApiClient();

            services.AddSingleton<SnykCliRunner>();
            services.AddSingleton<CliProductScanRunner>();
            services.AddSingleton<DepGraphGenerator>();
            services.AddSingleton<SnykMonitor>();
            services.AddSingleton<SnykProjectUrlResolver>();
            services.AddSingleton<SnykProjectCleanupService>();

            if (snyk.Engines.OpenSource == ScanEngine.Api)
            {
                services.AddSingleton<IOpenSourceScanner, ApiOpenSourceScanner>();
            }
            else
            {
                services.AddSingleton<IOpenSourceScanner, CliOpenSourceScanner>();
            }

            if (snyk.Engines.Code == ScanEngine.Api)
            {
                services.AddSingleton<ICodeScanner, ApiCodeScanner>();
            }
            else
            {
                services.AddSingleton<ICodeScanner, CliCodeScanner>();
            }

            services.AddSingleton<IIacScanner, CliIacScanner>();

            return services;
        }

        /// <summary>
        /// Rejects a pre-release API version. Snyk serves the Test API only on GA versions: a
        /// <c>~beta</c> or <c>~experimental</c> suffix returns 404 for an otherwise valid request, and the
        /// project and target endpoints behind project links and branch cleanup are equally unreliable there.
        /// </summary>
        internal static void ValidateApiVersion(SnykOptions snyk)
        {
            if (snyk.RestApiVersion.Contains('~', StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    $"Snyk:RestApiVersion '{snyk.RestApiVersion}' is a pre-release channel. Snyk serves the Test API " +
                    "only on GA versions; a '~beta' or '~experimental' suffix returns 404. Use a date-stamped GA " +
                    "version such as '2026-03-25'.");
            }
        }

        /// <summary>
        /// Fails fast on engine settings Snyk's Test API cannot honor. Both conditions otherwise surface only
        /// as every scan of that product erroring, long after deployment.
        /// </summary>
        internal static void ValidateEngines(SnykOptions snyk)
        {
            if (snyk.Engines.Iac == ScanEngine.Api)
            {
                throw new InvalidOperationException(
                    "Snyk:Engines:Iac cannot be 'Api'. Snyk's Test API accepts an 'iac' scan configuration but no " +
                    "resource type produces an IaC scan component, so every submitted IaC test fails to assemble. " +
                    "Use 'Cli' until Snyk ships IaC support on the Test API.");
            }

            if (snyk.Engines.Code == ScanEngine.Api && string.IsNullOrWhiteSpace(snyk.ScmIntegrationId))
            {
                throw new InvalidOperationException(
                    "Snyk:Engines:Code is 'Api' but Snyk:ScmIntegrationId is not set. The API-backed Code scan reads " +
                    "repository source through a Snyk SCM integration, so it needs that integration's id.");
            }
        }
    }
}
