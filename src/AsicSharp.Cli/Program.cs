using System.CommandLine;
using System.CommandLine.Invocation;
using AsicSharp.Configuration;
using AsicSharp.Extensions;
using AsicSharp.Models;
using AsicSharp.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace AsicSharp.Cli;

internal static class Program
{
    static async Task<int> Main(string[] args)
    {
        var rootCommand = new RootCommand("ASiC Timestamp Container Tool — create and verify RFC 3161 timestamped containers (ASiC-S and ASiC-E)")
        {
            BuildStampCommand(),
            BuildVerifyCommand(),
            BuildRenewCommand(),
            BuildExtractCommand(),
            BuildInfoCommand()
        };

        return await rootCommand.InvokeAsync(args);
    }

    private static Command BuildStampCommand()
    {
        var fileArg = new Argument<FileInfo[]>("file", "The file(s) to timestamp (multiple files create an ASiC-E container)")
        {
            Arity = ArgumentArity.OneOrMore
        };
        var outputOption = new Option<FileInfo?>(
            ["--output", "-o"],
            "Output path for the container (defaults to <file>.asics or <file>.asice)");
        var tsaOption = new Option<string[]>(
            ["--tsa", "-t"],
            "Timestamp Authority URL(s) — first is primary, rest are fallbacks (default: DigiCert)")
        {
            Arity = ArgumentArity.OneOrMore
        };
        var algorithmOption = new Option<string>(
            ["--algorithm", "-a"],
            () => "SHA256",
            "Hash algorithm (SHA256, SHA384, SHA512)");

        var cmd = new Command("stamp", "Create an ASiC container with a timestamp for one or more files")
        {
            fileArg, outputOption, tsaOption, algorithmOption
        };

        cmd.SetHandler(async (InvocationContext ctx) =>
        {
            var files = ctx.ParseResult.GetValueForArgument(fileArg);
            var output = ctx.ParseResult.GetValueForOption(outputOption);
            var tsaUrls = ctx.ParseResult.GetValueForOption(tsaOption);
            var algorithm = ctx.ParseResult.GetValueForOption(algorithmOption)!;

            foreach (var file in files)
            {
                if (!file.Exists)
                {
                    Console.Error.WriteLine($"Error: File not found: {file.FullName}");
                    ctx.ExitCode = 1;
                    return;
                }
            }

            bool isExtended = files.Length > 1;
            var defaultExt = isExtended ? AsicConstants.ExtensionExtended : AsicConstants.Extension;
            var outputPath = output?.FullName ?? files[0].FullName + defaultExt;

            var hashAlgorithm = algorithm.ToUpperInvariant() switch
            {
                "SHA256" => System.Security.Cryptography.HashAlgorithmName.SHA256,
                "SHA384" => System.Security.Cryptography.HashAlgorithmName.SHA384,
                "SHA512" => System.Security.Cryptography.HashAlgorithmName.SHA512,
                _ => throw new ArgumentException($"Unsupported algorithm: {algorithm}")
            };

            using var services = BuildServiceProvider(tsaUrls, hashAlgorithm);
            var asicService = services.GetRequiredService<IAsicService>();

            var format = isExtended ? "ASiC-E" : "ASiC-S";
            Console.WriteLine($"Format:       {format}");
            foreach (var file in files)
                Console.WriteLine($"Timestamping: {file.FullName}");
            Console.WriteLine($"TSA:          {string.Join(", ", tsaUrls ?? [WellKnownTsa.DigiCert])}");
            Console.WriteLine($"Algorithm:    {hashAlgorithm.Name}");
            Console.WriteLine();

            try
            {
                AsicCreateResult result;
                if (isExtended)
                {
                    result = await asicService.CreateExtendedFromFilesAsync(
                        files.Select(f => f.FullName), ctx.GetCancellationToken());
                }
                else
                {
                    result = await asicService.CreateFromFileAsync(files[0].FullName, ctx.GetCancellationToken());
                }

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
        var fileArg = new Argument<FileInfo>("container", "The .asics/.asice container file to verify");
        var verboseOption = new Option<bool>(
            ["--verbose", "-v"],
            "Show detailed verification steps");

        var cmd = new Command("verify", "Verify an ASiC container (ASiC-S or ASiC-E)")
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
                if (result.FileNames is { Count: > 1 })
                {
                    Console.WriteLine($"  Files:      {string.Join(", ", result.FileNames)}");
                }
                else
                {
                    Console.WriteLine($"  File:       {result.FileName}");
                }
                Console.WriteLine($"  Timestamp:  {result.Timestamp:O}");
                Console.WriteLine($"  Hash:       {result.DataHash} ({result.HashAlgorithm})");

                if (result.TimestampChain is { Count: > 1 })
                {
                    Console.WriteLine();
                    Console.WriteLine("  Timestamp chain:");
                    foreach (var entry in result.TimestampChain)
                    {
                        var icon = entry.IsValid ? "✓" : "✗";
                        Console.WriteLine($"    {icon} [{entry.Order}] {entry.Timestamp:O} ({System.IO.Path.GetFileName(entry.EntryName)})");
                        if (entry.TsaCertificate != null)
                            Console.WriteLine($"          TSA: {entry.TsaCertificate.Subject}");
                    }
                }
                else
                {
                    if (result.TsaCertificate != null)
                        Console.WriteLine($"  TSA Cert:   {result.TsaCertificate.Subject}");
                }

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

    private static Command BuildRenewCommand()
    {
        var fileArg = new Argument<FileInfo>("container", "The .asics/.asice container file to renew");
        var tsaOption = new Option<string[]>(
            ["--tsa", "-t"],
            "Timestamp Authority URL(s) — first is primary, rest are fallbacks (default: DigiCert)")
        {
            Arity = ArgumentArity.OneOrMore
        };
        var algorithmOption = new Option<string>(
            ["--algorithm", "-a"],
            () => "SHA256",
            "Hash algorithm (SHA256, SHA384, SHA512)");

        var cmd = new Command("renew", "Renew the timestamp on an ASiC container for long-term archival")
        {
            fileArg, tsaOption, algorithmOption
        };

        cmd.SetHandler(async (InvocationContext ctx) =>
        {
            var file = ctx.ParseResult.GetValueForArgument(fileArg);
            var tsaUrls = ctx.ParseResult.GetValueForOption(tsaOption);
            var algorithm = ctx.ParseResult.GetValueForOption(algorithmOption)!;

            if (!file.Exists)
            {
                Console.Error.WriteLine($"Error: File not found: {file.FullName}");
                ctx.ExitCode = 1;
                return;
            }

            var hashAlgorithm = algorithm.ToUpperInvariant() switch
            {
                "SHA256" => System.Security.Cryptography.HashAlgorithmName.SHA256,
                "SHA384" => System.Security.Cryptography.HashAlgorithmName.SHA384,
                "SHA512" => System.Security.Cryptography.HashAlgorithmName.SHA512,
                _ => throw new ArgumentException($"Unsupported algorithm: {algorithm}")
            };

            using var services = BuildServiceProvider(tsaUrls, hashAlgorithm);
            var asicService = services.GetRequiredService<IAsicService>();

            Console.WriteLine($"Renewing:   {file.FullName}");
            Console.WriteLine($"TSA:        {string.Join(", ", tsaUrls ?? [WellKnownTsa.DigiCert])}");
            Console.WriteLine($"Algorithm:  {hashAlgorithm.Name}");
            Console.WriteLine();

            try
            {
                var result = await asicService.RenewFileAsync(file.FullName, ctx.GetCancellationToken());

                File.WriteAllBytes(file.FullName, result.ContainerBytes);

                Console.WriteLine($"✓ Renewed:    {result.Timestamp:O}");
                Console.WriteLine($"  Token hash: {result.DataHash}");
                Console.WriteLine($"  Output:     {file.FullName}");
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

    private static Command BuildExtractCommand()
    {
        var fileArg = new Argument<FileInfo>("container", "The .asics/.asice container file");
        var outputOption = new Option<DirectoryInfo?>(
            ["--output", "-o"],
            "Output directory (defaults to current directory)");

        var cmd = new Command("extract", "Extract files from an ASiC container (ASiC-S or ASiC-E)")
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
                var files = asicService.ExtractAll(containerBytes);

                Directory.CreateDirectory(outputDir);
                foreach (var (fileName, data) in files)
                {
                    var outputPath = Path.Combine(outputDir, fileName);
                    File.WriteAllBytes(outputPath, data);
                    Console.WriteLine($"Extracted: {outputPath} ({data.Length:N0} bytes)");
                }
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
        string[]? tsaUrls = null,
        System.Security.Cryptography.HashAlgorithmName? hashAlgorithm = null)
    {
        var services = new ServiceCollection();

        services.AddLogging(builder => builder
            .AddConsole()
            .SetMinimumLevel(LogLevel.Warning));

        services.AddAsicSharp(options =>
        {
            if (tsaUrls is { Length: > 0 })
            {
                options.TimestampAuthorityUrl = tsaUrls[0];
                options.TimestampAuthorityUrls = tsaUrls.ToList();
            }
            if (hashAlgorithm.HasValue) options.HashAlgorithm = hashAlgorithm.Value;
        });

        return services.BuildServiceProvider();
    }
}
