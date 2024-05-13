using EKS_Windows_Bootstrapper;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System.Diagnostics;
using System.Runtime.InteropServices;
class Program
{
    static void Main(string[] args)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            WindowsOnlyCode(args);
        }
        else
        {
            // Handle unsupported operating system
            Console.WriteLine("This application only supports Windows operating system.");
            return;
        }
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    static void WindowsOnlyCode(string[] args)
    {
        if (!EventLog.SourceExists("EKS Windows Bootstrapper"))
        {
            EventLog.CreateEventSource("EKS Windows Bootstrapper", "Application");
        }
        HostApplicationBuilder builder = Host.CreateApplicationBuilder(args);
        builder.Logging.ClearProviders();
        builder.Logging.AddConsole();
        builder.Logging.AddEventLog(x =>
        {
            x.SourceName = "EKS Windows Bootstrapper";
            x.Filter = (source, logLevel) => logLevel >= LogLevel.Information; // Modify the log level to include LogLevel.Information
        });
        builder.Services.AddWindowsService(options =>
        {
            options.ServiceName = "EKS Windows Bootstrapper";
        });
        builder.Services.AddHostedService<BootstrapperService>();

        var host = builder.Build();
        host.Run();
    }
}

