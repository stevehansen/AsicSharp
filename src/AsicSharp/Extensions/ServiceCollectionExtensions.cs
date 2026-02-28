using AsicSharp.Configuration;
using AsicSharp.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AsicSharp.Extensions;

/// <summary>
/// Extension methods for registering ASiC timestamp services with DI.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Add ASiC timestamp services to the DI container with default options (DigiCert TSA, SHA-256).
    /// </summary>
    public static IServiceCollection AddAsicSharp(this IServiceCollection services)
    {
        return services.AddAsicSharp(_ => { });
    }

    /// <summary>
    /// Add ASiC timestamp services to the DI container with custom options.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">Action to configure <see cref="AsicTimestampOptions"/>.</param>
    public static IServiceCollection AddAsicSharp(
        this IServiceCollection services,
        Action<AsicTimestampOptions> configure)
    {
        services.Configure(configure);

        // Register the typed HttpClient for TsaClient
        services.AddHttpClient<ITsaClient, TsaClient>((sp, client) =>
        {
            var options = sp.GetRequiredService<IOptions<AsicTimestampOptions>>().Value;
            client.Timeout = options.Timeout;
            client.DefaultRequestHeaders.Accept.Add(
                new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/timestamp-reply"));
        });

        services.AddTransient<IAsicService, AsicService>();

        return services;
    }

    /// <summary>
    /// Add ASiC timestamp services using configuration binding (e.g., from appsettings.json).
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configurationSection">The configuration section to bind.</param>
    public static IServiceCollection AddAsicSharp(
        this IServiceCollection services,
        Microsoft.Extensions.Configuration.IConfigurationSection configurationSection)
    {
        services.Configure<AsicTimestampOptions>(configurationSection);

        services.AddHttpClient<ITsaClient, TsaClient>((sp, client) =>
        {
            var options = sp.GetRequiredService<IOptions<AsicTimestampOptions>>().Value;
            client.Timeout = options.Timeout;
            client.DefaultRequestHeaders.Accept.Add(
                new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/timestamp-reply"));
        });

        services.AddTransient<IAsicService, AsicService>();

        return services;
    }
}
