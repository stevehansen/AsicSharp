using AsicSharp.Configuration;
using AsicSharp.Extensions;
using AsicSharp.Services;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
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
}
