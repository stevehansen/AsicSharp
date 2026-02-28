using AsicSharp.Configuration;
using AsicSharp.Extensions;
using AsicSharp.Services;
using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace AsicSharp.Tests;

public class DependencyInjectionTests
{
    [Fact]
    public void AddAsicSharp_ShouldResolveServices()
    {
        var services = new ServiceCollection();
        services.AddAsicSharp();

        using var provider = services.BuildServiceProvider();

        provider.GetService<ITsaClient>().Should().NotBeNull();
        provider.GetService<IAsicService>().Should().NotBeNull();
    }

    [Fact]
    public void AddAsicSharp_WithCustomOptions_ShouldApply()
    {
        var services = new ServiceCollection();
        services.AddAsicSharp(options =>
        {
            options.TimestampAuthorityUrl = WellKnownTsa.Sectigo;
            options.HashAlgorithm = System.Security.Cryptography.HashAlgorithmName.SHA512;
        });

        using var provider = services.BuildServiceProvider();

        var asicService = provider.GetRequiredService<IAsicService>();
        asicService.Should().NotBeNull();
    }

    [Fact]
    public void AddAsicSharp_ShouldRegisterTypedHttpClient()
    {
        var services = new ServiceCollection();
        services.AddAsicSharp();

        using var provider = services.BuildServiceProvider();

        // ITsaClient should be resolvable (backed by typed HttpClient)
        var tsaClient = provider.GetRequiredService<ITsaClient>();
        tsaClient.Should().BeOfType<TsaClient>();
    }

    [Fact]
    public void AddAsicSharp_WithConfigurationSection_ShouldBindOptions()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["AsicTimestamp:TimestampAuthorityUrl"] = WellKnownTsa.Sectigo,
                ["AsicTimestamp:UseNonce"] = "false",
                ["AsicTimestamp:RequestSignerCertificates"] = "false"
            })
            .Build();

        var services = new ServiceCollection();
        services.AddAsicSharp(config.GetSection(AsicTimestampOptions.SectionName));

        using var provider = services.BuildServiceProvider();

        var options = provider.GetRequiredService<IOptions<AsicTimestampOptions>>().Value;
        options.TimestampAuthorityUrl.Should().Be(WellKnownTsa.Sectigo);
        options.UseNonce.Should().BeFalse();
        options.RequestSignerCertificates.Should().BeFalse();
    }
}
