using System.CommandLine;
using System.CommandLine.Invocation;
using AsicSharp.Configuration;
using AsicSharp.Extensions;
using AsicSharp.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace AsicSharp.Cli;

internal static class Program
{
    static async Task<int> Main(string[] args)
    {
        var rootCommand = new RootCommand("ASiC-S Timestamp Container Tool — create and verify RFC 3161 timestamped containers")
        {
            BuildStampCommand(),
            BuildVerifyCommand(),
            BuildExtractCommand(),
            BuildInfoCommand()
        };

        return await rootCommand.InvokeAsync(args);
    }

    private static Command BuildStampCommand()
    {
        var fileArg = new Argument<FileInfo>("file", "The file to timestamp");
        var outputOption = new Option<FileInfo?>(
            ["--output", "-o"],
            "Output path for the .asics container (defaults to <file>.asics)");
        var tsaOption = new Option<string>(
            ["--tsa", "-t"],
            () => WellKnownTsa.DigiCert,
            "Timestamp Authority URL");
        var algorithmOption = new Option<string>(
            ["--algorithm", "-a"],
            () => "SHA256",
            "Hash algorithm (SHA256, SHA384, SHA512)");

        var cmd = new Command("stamp", "Create an ASiC-S container with a timestamp for a file")
        {
            fileArg, outputOption, tsaOption, algorithmOption
        };

        cmd.SetHandler(async (InvocationContext ctx) =>
        {
            var file = ctx.ParseResult.GetValueForArgument(fileArg);
            var output = ctx.ParseResult.GetValueForOption(outputOption);
            var tsa = ctx.ParseResult.GetValueForOption(tsaOption)!;
            var algorithm = ctx.ParseResult.GetValueForOption(algorithmOption)!;

            if (!file.Exists)
            {
                Console.Error.WriteLine($"Error: File not found: {file.FullName}");
                ctx.ExitCode = 1;
                return;
            }

            var outputPath = output?.FullName ?? file.FullName + AsicConstants.Extension;

            var hashAlgorithm = algorithm.ToUpperInvariant() switch
            {
                "SHA256" => System.Security.Cryptography.HashAlgorithmName.SHA256,
                "SHA384" => System.Security.Cryptography.HashAlgorithmName.SHA384,
                "SHA512" => System.Security.Cryptography.HashAlgorithmName.SHA512,
                _ => throw new ArgumentException($"Unsupported algorithm: {algorithm}")
            };

            using var services = BuildServiceProvider(tsa, hashAlgorithm);
            var asicService = services.GetRequiredService<IAsicService>();

            Console.WriteLine($"Timestamping: {file.FullName}");
            Console.WriteLine($"TSA:          {tsa}");
            Console.WriteLine($"Algorithm:    {hashAlgorithm.Name}");
            Console.WriteLine();

            try
            {
                var result = await asicService.CreateFromFileAsync(file.FullName, ctx.GetCancellationToken());

                File.WriteAllBytes(outputPath, result.ContainerBytes);

                Console.WriteLine($"✓ Timestamp:  {result.Timestamp:O}");
                Console.WriteLine($"  Hash:       {result.DataHash}");
                Console.WriteLine($"  Output:     {outputPath}");
                Console.WriteLine($"  Size:       {result.ContainerBytes.Length:N0} bytes");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error: {ex.Message}");
                ctx.ExitCode = 1;
            }
        });

        return cmd;
    }

    private static Command BuildVerifyCommand()
    {
        var fileArg = new Argument<FileInfo>("container", "The .asics container file to verify");
        var verboseOption = new Option<bool>(
            ["--verbose", "-v"],
            "Show detailed verification steps");

        var cmd = new Command("verify", "Verify an ASiC-S container")
        {
            fileArg, verboseOption
        };

        cmd.SetHandler((InvocationContext ctx) =>
        {
            var file = ctx.ParseResult.GetValueForArgument(fileArg);
            var verbose = ctx.ParseResult.GetValueForOption(verboseOption);

            if (!file.Exists)
            {
                Console.Error.WriteLine($"Error: File not found: {file.FullName}");
                ctx.ExitCode = 1;
                return;
            }

            using var services = BuildServiceProvider();
            var asicService = services.GetRequiredService<IAsicService>();

            Console.WriteLine($"Verifying: {file.FullName}");
            Console.WriteLine();

            var result = asicService.VerifyFile(file.FullName);

            if (verbose)
            {
                Console.WriteLine("Verification steps:");
                foreach (var step in result.Steps)
                {
                    var icon = step.Passed ? "✓" : "✗";
                    Console.WriteLine($"  {icon} {step.Name}: {step.Detail}");
                }
                Console.WriteLine();
            }

            if (result.IsValid)
            {
                Console.WriteLine($"✓ VALID");
                Console.WriteLine($"  File:       {result.FileName}");
                Console.WriteLine($"  Timestamp:  {result.Timestamp:O}");
                Console.WriteLine($"  Hash:       {result.DataHash} ({result.HashAlgorithm})");

                if (result.TsaCertificate != null)
                    Console.WriteLine($"  TSA Cert:   {result.TsaCertificate.Subject}");

                if (result.SigningCertificate != null)
                    Console.WriteLine($"  Signed by:  {result.SigningCertificate.Subject}");

                ctx.ExitCode = 0;
            }
            else
            {
                Console.Error.WriteLine($"✗ INVALID: {result.Error}");
                ctx.ExitCode = 1;
            }
        });

        return cmd;
    }

    private static Command BuildExtractCommand()
    {
        var fileArg = new Argument<FileInfo>("container", "The .asics container file");
        var outputOption = new Option<DirectoryInfo?>(
            ["--output", "-o"],
            "Output directory (defaults to current directory)");

        var cmd = new Command("extract", "Extract the original file from an ASiC-S container")
        {
            fileArg, outputOption
        };

        cmd.SetHandler((InvocationContext ctx) =>
        {
            var file = ctx.ParseResult.GetValueForArgument(fileArg);
            var outputDir = ctx.ParseResult.GetValueForOption(outputOption)?.FullName ?? Directory.GetCurrentDirectory();

            if (!file.Exists)
            {
                Console.Error.WriteLine($"Error: File not found: {file.FullName}");
                ctx.ExitCode = 1;
                return;
            }

            using var services = BuildServiceProvider();
            var asicService = services.GetRequiredService<IAsicService>();

            try
            {
                var containerBytes = File.ReadAllBytes(file.FullName);
                var (fileName, data) = asicService.Extract(containerBytes);

                var outputPath = Path.Combine(outputDir, fileName);
                Directory.CreateDirectory(outputDir);
                File.WriteAllBytes(outputPath, data);

                Console.WriteLine($"Extracted: {outputPath} ({data.Length:N0} bytes)");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error: {ex.Message}");
                ctx.ExitCode = 1;
            }
        });

        return cmd;
    }

    private static Command BuildInfoCommand()
    {
        var cmd = new Command("info", "Show well-known Timestamp Authority URLs");

        cmd.SetHandler(() =>
        {
            Console.WriteLine("Well-known RFC 3161 Timestamp Authorities:");
            Console.WriteLine();
            Console.WriteLine($"  DigiCert:    {WellKnownTsa.DigiCert}");
            Console.WriteLine($"  Sectigo:     {WellKnownTsa.Sectigo}");
            Console.WriteLine($"  GlobalSign:  {WellKnownTsa.GlobalSign}");
            Console.WriteLine($"  FreeTSA:     {WellKnownTsa.FreeTsa}");
            Console.WriteLine($"  Apple:       {WellKnownTsa.Apple}");
            Console.WriteLine($"  Entrust:     {WellKnownTsa.Entrust}");
        });

        return cmd;
    }

    private static ServiceProvider BuildServiceProvider(
        string? tsaUrl = null,
        System.Security.Cryptography.HashAlgorithmName? hashAlgorithm = null)
    {
        var services = new ServiceCollection();

        services.AddLogging(builder => builder
            .AddConsole()
            .SetMinimumLevel(LogLevel.Warning));

        services.AddAsicSharp(options =>
        {
            if (tsaUrl != null) options.TimestampAuthorityUrl = tsaUrl;
            if (hashAlgorithm.HasValue) options.HashAlgorithm = hashAlgorithm.Value;
        });

        return services.BuildServiceProvider();
    }
}
