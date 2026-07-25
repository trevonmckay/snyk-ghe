using Microsoft.Extensions.DependencyInjection;

namespace Snyk.Client
{
    public static class SnykApiClientServiceCollectionExtensions
    {
        /// <summary>
        /// Registers <see cref="SnykApiClient"/> and the two named HTTP clients it needs. The host must
        /// register an <see cref="ISnykTokenProvider"/> and configure <see cref="SnykApiOptions"/>.
        /// </summary>
        public static IServiceCollection AddSnykApiClient(this IServiceCollection services)
        {
            services.AddHttpClient(SnykApiClient.HttpClientName);

            services.AddHttpClient(SnykApiClient.NoRedirectHttpClientName)
                .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler { AllowAutoRedirect = false });

            services.AddSingleton<SnykApiClient>();
            return services;
        }
    }
}
