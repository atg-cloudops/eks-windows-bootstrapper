using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace EKS_Windows_Bootstrapper;

public partial class BootstrapperService(ILogger<BootstrapperService> logger, IConfiguration configuration) : BackgroundService
{
    [GeneratedRegex(@"-EKSClusterName\s+(['""])(.*?)\1")]
    private static partial Regex EKSClusterNameRegex();

    [GeneratedRegex(@"-DNSClusterIP\s+(['""])(.*?)\1")]
    private static partial Regex DNSClusterIPRegex();

    [GeneratedRegex(@"-KubeletExtraArgs\s+(['""])(.*?)\1")]
    private static partial Regex KubeletExtraArgsRegex();

    [GeneratedRegex(@"-KubeProxyExtraArgs\s+(['""])(.*?)\1")]
    private static partial Regex KubeProxyExtraArgsRegex();

    [GeneratedRegex(@"""Success"":\s*(true|false)")]
    private static partial Regex HNSSuccessRegex();
    private const string ServiceNameKubelet = "kubelet";
    private const string ServiceNameKubeProxy = "kube-proxy";
    private const string ServiceNameContainerd = "containerd";
    private const string ResolvDirectory = @"c:\etc";
    private const string CniConfigFileName = "vpc-bridge.conf";
    private const string VpcBridgeNetworkType = "L2Bridge";
    private const string CniSpecVersion = "0.4.0";
    private const string CniNetworkName = "vpc";
    private const string CniNetworkType = "vpc-bridge";
    private const string ContainerdPipeEndpoint = "npipe:////./pipe/containerd-containerd";
    private const int UserdataPollIntervalMs = 200;
    private const int UserdataTimeoutMinutes = 1;
    private const int AwsRetryMaxAttempts = 5;
    private const int AwsRetryDelayMs = 2000;

    // Route targets for AWS/metadata and related services (link-local)
    private static readonly string[] MetadataRouteAddresses = { "169.254.169.254", "169.254.169.250", "169.254.169.251", "169.254.169.249", "169.254.169.123", "169.254.169.253" };

    [DllImport("vmcompute.dll")]
    private static extern void HNSCall(
        [MarshalAs(UnmanagedType.LPWStr)] string method,
        [MarshalAs(UnmanagedType.LPWStr)] string path,
        [MarshalAs(UnmanagedType.LPWStr)] string request,
        [MarshalAs(UnmanagedType.LPWStr)] out string response);

    readonly bool _shutdownOnCriticalFailure = bool.TryParse(configuration["ShutdownOnCriticalFailure"], out var shutdownOnCritical) && shutdownOnCritical;
    string[]? vpcCIDRRanges;
    string? vpcCIDR;
    string? subnetCIDRRange;
    string? excludedSnatCIDRsEnvVar;
    string? dnsClusterIP;
    string? apiVersionAuthentication;
    string? kubeletExtraArgs;
    string? kubeProxyExtraArgs;
    string? cniConfigDir;
    string? iamAuthenticator;
    string? eksClusterCACertFile;
    string? kubelet;
    string? kubeproxy;
    string? credentialProviderDir;
    string? credentialProviderConfig;
    string? kubeConfigFile;
    string? kubeletConfigFile;
    string? serviceHostExe;
    string? region;
    string? clusterEndpoint;
    string? clusterCertificateAuthorityData;
    string? serviceCIDR;
    string? privateDnsName;
    string? subnetMaskBits;
    string? internalIp;
    string? eniMACAddress;
    string? clusterName;
    string? kubeLogLevel;
    string[]? gatewayIpAddresses;
    const int SERVICE_FAILURE_COUNT_RESET_SEC = 300;
    const int SERVICE_FAILURE_FIRST_DELAY_MS = 5000;
    const int SERVICE_FAILURE_SECOND_DELAY_MS = 30000;
    const int SERVICE_FAILURE_THIRD_DELAY_MS = 60000;
    readonly ILogger<BootstrapperService> _logger = logger;
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Gathering system configuration...");
        var stopWatch = new Stopwatch();
        stopWatch.Start();

        var userData = string.Empty;
        var stopwatch = Stopwatch.StartNew();
        _logger.LogInformation("Waiting for userdata...");
        while (stopwatch.Elapsed < TimeSpan.FromMinutes(UserdataTimeoutMinutes))
        {
            try
            {
                userData = Amazon.Util.EC2InstanceMetadata.UserData;
                if (!string.IsNullOrEmpty(userData))
                {
                    if (_logger.IsEnabled(LogLevel.Information))
                        _logger.LogInformation("Userdata received, took {ElapsedMs} ms", stopwatch.ElapsedMilliseconds);
                    break;
                }
                await Task.Delay(UserdataPollIntervalMs, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while retrieving userdata, Retrying...");
            }
        }
        stopwatch.Stop();
        if (_logger.IsEnabled(LogLevel.Information))
            _logger.LogInformation("Userdata: {UserData}", userData);
        if (string.IsNullOrEmpty(userData))
        {
            _logger.LogError("Userdata is empty, exiting...");
            return;
        }

        clusterName = EKSClusterNameRegex().Match(userData)?.Groups[2]?.Value ?? throw new ArgumentException("Cluster name was not found in userdata, exiting");
        dnsClusterIP = DNSClusterIPRegex().Match(userData)?.Groups[2]?.Value ?? throw new ArgumentException("DnsClusterIP was not found in userdata, exiting");
        kubeletExtraArgs = KubeletExtraArgsRegex().Match(userData)?.Groups[2]?.Value ?? string.Empty;
        kubeProxyExtraArgs = KubeProxyExtraArgsRegex().Match(userData)?.Groups[2]?.Value ?? string.Empty;

        if (_logger.IsEnabled(LogLevel.Information))
            _logger.LogInformation("Extracted parameters: ClusterName: {ClusterName}, DnsClusterIP: {DnsClusterIP}, KubeletExtraArgs: {KubeletExtraArgs}, KubeProxyExtraArgs: {KubeProxyExtraArgs}",
                clusterName, dnsClusterIP, kubeletExtraArgs, kubeProxyExtraArgs);

        var programFilesDirectory = Environment.GetEnvironmentVariable("ProgramFiles") ?? "C:\\Program Files";
        var programDataDirectory = Environment.GetEnvironmentVariable("ProgramData") ?? "C:\\ProgramData";
        var startScript = Environment.GetEnvironmentVariable("EKS_BOOTSTRAPPER_START_SCRIPT") ?? null;
        apiVersionAuthentication = Environment.GetEnvironmentVariable("API_VERSION_AUTHENTICATION") ?? "client.authentication.k8s.io/v1beta1";

        // This program starts with windows services on EC2 to bootstrap a EKS windows node
        // It waits for userdata to become available and then extracts the necessary information to join the EKS cluster from the pwsh command
        // It then prepares the node and starts the kubernetes components.
        var eksBinDir = Path.Combine(programFilesDirectory, "Amazon", "EKS");
        var eksDataDir = Path.Combine(programDataDirectory, "Amazon", "EKS");
        cniConfigDir = Path.Combine(eksDataDir, "cni", "config");
        iamAuthenticator = Path.Combine(eksBinDir, "aws-iam-authenticator.exe");
        eksClusterCACertFile = Path.Combine(eksDataDir, "cluster_ca.crt");

        var kubernetesBinDir = Path.Combine(programFilesDirectory, "kubernetes");
        var kubernetesDataDir = Path.Combine(programDataDirectory, "kubernetes");
        kubelet = Path.Combine(kubernetesBinDir, "kubelet.exe");
        kubeproxy = Path.Combine(kubernetesBinDir, "kube-proxy.exe");
        credentialProviderDir = Path.Combine(eksBinDir, "credential-providers");
        credentialProviderConfig = Path.Combine(eksBinDir, "ecr-credential-provider-config.json");

        // KUBECONFIG environment variable is set by Install-EKSWorkerNode.ps1
        kubeConfigFile = Environment.GetEnvironmentVariable("KUBECONFIG", EnvironmentVariableTarget.Machine) ?? Path.Combine(kubernetesDataDir, "kubeconfig");

        // Kubelet configuration file
        kubeletConfigFile = Path.Combine(kubernetesDataDir, "kubelet-config.json");

        // Service host to host kubelet and kube-proxy
        serviceHostExe = Path.Combine(eksBinDir, "EKS-WindowsServiceHost.exe");

        // User defined environment variables
        excludedSnatCIDRsEnvVar = Environment.GetEnvironmentVariable("EXCLUDED_SNAT_CIDRS", EnvironmentVariableTarget.Machine); // e.g. '172.40.0.0/24,192.168.40.0/24'
        var serviceIpv4CIDREnvVar = Environment.GetEnvironmentVariable("SERVICE_IPV4_CIDR", EnvironmentVariableTarget.Machine); // e.g. '10.100.0.0/16'

        var envLogLevel = Environment.GetEnvironmentVariable("EKSKUBELOGLEVEL", EnvironmentVariableTarget.Machine);
        kubeLogLevel = int.TryParse(envLogLevel, out var parsedLevel) && parsedLevel >= 1 && parsedLevel <= 8
            ? envLogLevel!
            : "1";

        var instanceId = Amazon.Util.EC2InstanceMetadata.InstanceId;
        var ec2Client = new Amazon.EC2.AmazonEC2Client();
        var client = new Amazon.EKS.AmazonEKSClient();

        var clusterTask = DescribeClusterWithRetryAsync(client, clusterName!, stoppingToken);
        var instanceInfoTask = DescribeInstancesWithRetryAsync(ec2Client, instanceId, stoppingToken);
        region = Amazon.Util.EC2InstanceMetadata.Region.SystemName;
        eniMACAddress = Amazon.Util.EC2InstanceMetadata.GetData("/mac");
        vpcCIDRRanges = Amazon.Util.EC2InstanceMetadata.GetData($"/network/interfaces/macs/{eniMACAddress}/vpc-ipv4-cidr-blocks")
            ?.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        vpcCIDR = Amazon.Util.EC2InstanceMetadata.GetData($"/network/interfaces/macs/{eniMACAddress}/vpc-ipv4-cidr-block");
        subnetCIDRRange = Amazon.Util.EC2InstanceMetadata.GetData($"/network/interfaces/macs/{eniMACAddress}/subnet-ipv4-cidr-block");
        var subnetParts = subnetCIDRRange?.Split("/", 2, StringSplitOptions.None);
        if (subnetParts == null || subnetParts.Length != 2)
            throw new ArgumentException("Subnet CIDR range was not found or invalid in instance metadata (expected format: prefix/maskBits).");
        subnetMaskBits = subnetParts[1];
        internalIp = Amazon.Util.EC2InstanceMetadata.PrivateIpAddress;

        var cluster = await clusterTask;
        clusterEndpoint = cluster.Cluster.Endpoint;
        clusterCertificateAuthorityData = cluster.Cluster.CertificateAuthority.Data;
        if (!string.IsNullOrEmpty(serviceIpv4CIDREnvVar))
        {
            serviceCIDR = serviceIpv4CIDREnvVar;
        }
        else if (!string.IsNullOrEmpty(cluster.Cluster.KubernetesNetworkConfig.ServiceIpv4Cidr))
        {
            serviceCIDR = cluster.Cluster.KubernetesNetworkConfig.ServiceIpv4Cidr;
        }
        else
        {
            serviceCIDR = vpcCIDRRanges?.Any(c => c.StartsWith("10.")) == true ? "172.20.0.0/16" : "10.100.0.0/16";
        }
        gatewayIpAddresses = [.. GetGatewayIpAddresses()];
        var instanceInfo = await instanceInfoTask;
        privateDnsName = instanceInfo.Reservations[0].Instances[0].PrivateDnsName;

        stopWatch.Stop();
        if (_logger.IsEnabled(LogLevel.Information))
            _logger.LogInformation("Gathered system configuration in {ElapsedMs} ms", stopWatch.ElapsedMilliseconds);
        stopWatch.Reset();

        _logger.LogInformation("Configuring EKS Windows Node");
        stopWatch.Start();
        await Task.WhenAll(
            ConfigureHNS(stoppingToken),
            startScript == null ? StartService(ServiceNameContainerd, stoppingToken) : ExecutePowershellScript(startScript, stoppingToken),
            UpdateKubeConfig(),
            UpdateEksCniConfig(),
            UpdateKubeletConfig(),
            RegisterKubernetesServices(stoppingToken),
            GenerateResolvConf()
        );
        await Task.WhenAll(
            StartService(ServiceNameKubelet, stoppingToken),
            StartService(ServiceNameKubeProxy, stoppingToken)
        );

        stopWatch.Stop();
        if (_logger.IsEnabled(LogLevel.Information))
            _logger.LogInformation("EKS Windows Node Configured in {ElapsedMs} ms", stopWatch.ElapsedMilliseconds);
    }


    async Task<Amazon.EKS.Model.DescribeClusterResponse> DescribeClusterWithRetryAsync(Amazon.EKS.IAmazonEKS client, string clusterName, CancellationToken cancellationToken)
    {
        for (var attempt = 1; attempt <= AwsRetryMaxAttempts; attempt++)
        {
            try
            {
                return await client.DescribeClusterAsync(new Amazon.EKS.Model.DescribeClusterRequest { Name = clusterName }, cancellationToken);
            }
            catch (Exception ex) when (attempt < AwsRetryMaxAttempts)
            {
                if (_logger.IsEnabled(LogLevel.Warning))
                    _logger.LogWarning(ex, "DescribeCluster attempt {Attempt} failed, retrying in {DelayMs} ms.", attempt, AwsRetryDelayMs);
                await Task.Delay(AwsRetryDelayMs, cancellationToken);
            }
        }
        return await client.DescribeClusterAsync(new Amazon.EKS.Model.DescribeClusterRequest { Name = clusterName }, cancellationToken);
    }

    async Task<Amazon.EC2.Model.DescribeInstancesResponse> DescribeInstancesWithRetryAsync(Amazon.EC2.IAmazonEC2 ec2Client, string instanceId, CancellationToken cancellationToken)
    {
        for (var attempt = 1; attempt <= AwsRetryMaxAttempts; attempt++)
        {
            try
            {
                return await ec2Client.DescribeInstancesAsync(new Amazon.EC2.Model.DescribeInstancesRequest { InstanceIds = new List<string> { instanceId } }, cancellationToken);
            }
            catch (Exception ex) when (attempt < AwsRetryMaxAttempts)
            {
                if (_logger.IsEnabled(LogLevel.Warning))
                    _logger.LogWarning(ex, "DescribeInstances attempt {Attempt} failed, retrying in {DelayMs} ms.", attempt, AwsRetryDelayMs);
                await Task.Delay(AwsRetryDelayMs, cancellationToken);
            }
        }
        return await ec2Client.DescribeInstancesAsync(new Amazon.EC2.Model.DescribeInstancesRequest { InstanceIds = new List<string> { instanceId } }, cancellationToken);
    }

    static IEnumerable<string> GetGatewayIpAddresses()
    {
        var netRoutes = NetworkInterface.GetAllNetworkInterfaces();
        foreach (var netRoute in netRoutes)
        {
            var ipProperties = netRoute.GetIPProperties();
            var gateways = ipProperties.GatewayAddresses;
            foreach (var gateway in gateways)
            {
                if (gateway.Address.AddressFamily == AddressFamily.InterNetwork)
                {
                    yield return gateway.Address.ToString();
                }
            }
        }
    }

    List<string> GetCombinedSNATExclusionList()
    {
        if (vpcCIDRRanges == null || vpcCIDRRanges.Length == 0)
        {
            throw new ArgumentNullException(nameof(vpcCIDRRanges));
        }
        List<string> combinedCIDRRange = [..vpcCIDRRanges];
        if (!string.IsNullOrEmpty(excludedSnatCIDRsEnvVar))
        {
            _logger.LogInformation("Excluding environment variable specified CIDR ranges for SNAT in CNI config");
            combinedCIDRRange.AddRange(excludedSnatCIDRsEnvVar.Split(',').Select(s => s.Trim()).Where(s => !string.IsNullOrEmpty(s)));
        }

        return combinedCIDRRange;
    }

    async Task UpdateKubeConfig()
    {
        if (string.IsNullOrEmpty(clusterCertificateAuthorityData))
        {
            throw new ArgumentNullException(nameof(clusterCertificateAuthorityData));
        }
        if (string.IsNullOrEmpty(eksClusterCACertFile))
        {
            throw new ArgumentNullException(nameof(eksClusterCACertFile));
        }
        if (string.IsNullOrEmpty(kubeConfigFile))
        {
            throw new ArgumentNullException(nameof(kubeConfigFile));
        }
        var caFileWriteTask = File.WriteAllBytesAsync(eksClusterCACertFile, Convert.FromBase64String(clusterCertificateAuthorityData));
        var kubeConfig = $@"
    apiVersion: v1
    kind: Config
    clusters:
    - cluster:
        certificate-authority: {eksClusterCACertFile}
        server: {clusterEndpoint}
      name: kubernetes
    contexts:
    - context:
        cluster: kubernetes
        user: kubelet
      name: kubelet
    current-context: kubelet
    users:
    - name: kubelet
      user:
        exec:
          apiVersion: {apiVersionAuthentication}
          command: {iamAuthenticator}
          args:
            - ""token""
            - ""-i""
            - ""{clusterName}""
            - --region
            - ""{region}""
    ";

        await Task.WhenAll(
            File.WriteAllTextAsync(kubeConfigFile, kubeConfig, Encoding.ASCII),
            caFileWriteTask
        );
    }

    async Task UpdateEksCniConfig()
    {
        var cniConfigFilePath = Path.Combine(cniConfigDir ?? string.Empty, CniConfigFileName);
        List<string> snatExcludedCIDRs = GetCombinedSNATExclusionList();
        var dnsSuffixList = new[] { "{%namespace%}.svc.cluster.local", "svc.cluster.local", "cluster.local" };
        var cniConfig = new CniConfig
        {
            CniVersion = CniSpecVersion,
            Name = CniNetworkName,
            Type = CniNetworkType,
            Capabilities = new CniCapabilities { PortMappings = true },
            DisableCheck = true,
            EniMACAddress = eniMACAddress ?? string.Empty,
            EniIPAddresses = [$"{internalIp}/{subnetMaskBits}"],
            GatewayIPAddress = gatewayIpAddresses?.FirstOrDefault(),
            VpcCIDRs = snatExcludedCIDRs,
            ServiceCIDR = serviceCIDR ?? string.Empty,
            Dns = new CniDnsConfig
            {
                Nameservers = [dnsClusterIP ?? string.Empty],
                Search = dnsSuffixList
            }
        };
        var json = JsonSerializer.Serialize(cniConfig, BootstrapperJsonContext.Default.CniConfig);
        await File.WriteAllTextAsync(cniConfigFilePath, json, Encoding.ASCII);
    }

    async Task UpdateKubeletConfig()
    {
        if (string.IsNullOrEmpty(kubeletConfigFile))
        {
            throw new ArgumentNullException(nameof(kubeletConfigFile));
        }
        var kubeletConfig = new KubeletConfiguration
        {
            Kind = "KubeletConfiguration",
            ApiVersion = "kubelet.config.k8s.io/v1beta1",
            Address = "0.0.0.0",
            Authentication = new KubeletAuthentication
            {
                Anonymous = new KubeletAnonymous { Enabled = false },
                Webhook = new KubeletWebhook { CacheTTL = "2m0s", Enabled = true },
                X509 = new KubeletX509 { ClientCAFile = eksClusterCACertFile }
            },
            Authorization = new KubeletAuthorization
            {
                Mode = "Webhook",
                Webhook = new KubeletAuthWebhook { CacheAuthorizedTTL = "5m0s", CacheUnauthorizedTTL = "30s" }
            },
            ClusterDomain = "cluster.local",
            HairpinMode = "hairpin-veth",
            CgroupDriver = "cgroupfs",
            CgroupRoot = "/",
            FeatureGates = new Dictionary<string, bool> { ["RotateKubeletServerCertificate"] = true },
            SerializeImagePulls = false,
            ServerTLSBootstrap = true,
            ClusterDNS = [dnsClusterIP ?? string.Empty]
        };
        var json = JsonSerializer.Serialize(kubeletConfig, BootstrapperJsonContext.Default.KubeletConfiguration);
        await File.WriteAllTextAsync(kubeletConfigFile, json, Encoding.ASCII);
    }

    async Task RegisterKubernetesServices(CancellationToken cancellationToken)
    {
        var kubeletArgs = new StringBuilder();
        kubeletArgs.Append(" --config=\\\"" + kubeletConfigFile + "\\\"");
        kubeletArgs.Append(" --cloud-provider=external");
        kubeletArgs.Append(" --kubeconfig=\\\"" + kubeConfigFile + "\\\"");
        kubeletArgs.Append(" --hostname-override=" + privateDnsName);
        kubeletArgs.Append(" --v=" + kubeLogLevel);
        kubeletArgs.Append(" --resolv-conf=\\\"\\\"");
        kubeletArgs.Append(" --enable-debugging-handlers");
        kubeletArgs.Append(" --cgroups-per-qos=false");
        kubeletArgs.Append(" --enforce-node-allocatable=\\\"\\\"");
        kubeletArgs.Append(" --container-runtime-endpoint=\\\"" + ContainerdPipeEndpoint + "\\\"");
        kubeletArgs.Append(" --image-credential-provider-bin-dir=\\\"" + credentialProviderDir + "\\\"");
        kubeletArgs.Append(" --image-credential-provider-config=\\\"" + credentialProviderConfig + "\\\"");
        kubeletArgs.Append(" --node-ip=" + internalIp);

        kubeletArgs.Append(" " + kubeletExtraArgs?.Replace("\"", "\\\""));

        var kubeletTask = Task.Run(() =>
        {
            RunScCreate(ServiceNameKubelet, $"\\\"{serviceHostExe}\\\" {ServiceNameKubelet} \\\"{kubelet}\\\" {kubeletArgs}");
            RunScFailure(ServiceNameKubelet);
            RunScFailureFlag(ServiceNameKubelet);
        }, cancellationToken);

        var kubeProxyArgs = string.Join(" ", new[]
        {
            $"--kubeconfig=\\\"{kubeConfigFile}\\\"",
            $"--v={kubeLogLevel}",
            "--proxy-mode=kernelspace",
            $"--hostname-override=\\\"{privateDnsName}\\\"",
            $"--cluster-cidr=\\\"{vpcCIDR}\\\"",
            kubeProxyExtraArgs ?? string.Empty
        });

        var kubeProxyTask = Task.Run(() =>
        {
            RunScCreate(ServiceNameKubeProxy, $"\\\"{serviceHostExe}\\\" {ServiceNameKubeProxy} \\\"{kubeproxy}\\\" {kubeProxyArgs}");
            RunScFailure(ServiceNameKubeProxy);
            RunScFailureFlag(ServiceNameKubeProxy);
        }, cancellationToken);

        await Task.WhenAll(kubeletTask, kubeProxyTask);
    }

    static void RunScCreate(string serviceName, string binPathArgs)
    {
        using var process = Process.Start(new ProcessStartInfo("sc.exe")
        {
            Arguments = $"create \"{serviceName}\" binPath= \"{binPathArgs}\" start= demand",
            UseShellExecute = false,
            CreateNoWindow = true
        });
        process?.WaitForExit();
    }

    static void RunScFailure(string serviceName)
    {
        using var process = Process.Start("sc.exe", $"failure {serviceName} reset={SERVICE_FAILURE_COUNT_RESET_SEC} actions=\"restart/{SERVICE_FAILURE_FIRST_DELAY_MS} + /restart/{SERVICE_FAILURE_SECOND_DELAY_MS} + /restart/{SERVICE_FAILURE_THIRD_DELAY_MS}\"");
        process?.WaitForExit();
    }

    static void RunScFailureFlag(string serviceName)
    {
        using var process = Process.Start("sc.exe", $"failureflag {serviceName} 1");
        process?.WaitForExit();
    }

    async Task GenerateResolvConf()
    {
        string resolvFile = Path.Combine(ResolvDirectory, "resolv.conf");

        if (!Directory.Exists(ResolvDirectory))
        {
            if (_logger.IsEnabled(LogLevel.Information))
                _logger.LogInformation("Creating resolv directory: {ResolvDir}", ResolvDirectory);
            Directory.CreateDirectory(ResolvDirectory);
        }

        // Getting unique comma separated Dns servers from the Ipv4 network interfaces (AddressFamily 2 represents IPv4)
        string[] dnsServers = NetworkInterface.GetAllNetworkInterfaces()
            .Where(ni => ni.Supports(NetworkInterfaceComponent.IPv4))
            .SelectMany(ni => ni.GetIPProperties().DnsAddresses)
            .Where(ip => ip.AddressFamily == AddressFamily.InterNetwork)
            .Select(ip => ip.ToString())
            .Distinct()
            .ToArray();

        string resolvContent = string.Join(Environment.NewLine, dnsServers.Select(s => $"nameserver {s}"));
        await File.WriteAllTextAsync(resolvFile, resolvContent, Encoding.ASCII);
    }

    async Task ExecutePowershellScript(string filePath, CancellationToken cancellationToken)
    {
        var scriptPath = Path.Combine(Environment.CurrentDirectory, filePath);
        using var process = Process.Start(new ProcessStartInfo("powershell.exe")
        {
            Arguments = $"-NoProfile -NoLogo -File \"{scriptPath}\"",
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true
        });
        if (process == null) throw new InvalidOperationException("Failed to start powershell process");
        var outputTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        await process.WaitForExitAsync(cancellationToken);
        var output = await outputTask;
        if (_logger.IsEnabled(LogLevel.Information))
        {
            _logger.LogInformation("Powershell script: {FilePath}", filePath);
            _logger.LogInformation("Powershell script output: {Output}", output);
        }
    }

    static async Task StartService(string serviceName, CancellationToken cancellationToken)
    {
        var process = Process.Start("sc.exe", $"start {serviceName}");
        if (process != null)
        {
            await process.WaitForExitAsync(cancellationToken);
        }
    }

    async Task ConfigureHNS(CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(eniMACAddress))
        {
            throw new InvalidOperationException("eniMACAddress must be set before configuring HNS.");
        }

        var vSwitchName = string.Format("vpcbr{0}", eniMACAddress.Replace(":", ""));
        Environment.SetEnvironmentVariable("KUBE_NETWORK", vSwitchName, EnvironmentVariableTarget.Machine);
        var prefixes = subnetCIDRRange?.Split(',', StringSplitOptions.RemoveEmptyEntries).Select(p => p.Trim()).ToArray() ?? [];
        var gateways = gatewayIpAddresses?[0]?.Split(',', StringSplitOptions.RemoveEmptyEntries).Select(g => g.Trim()).ToArray() ?? [];

        var hnsNetwork = new HnsNetworkRequest
        {
            Type = VpcBridgeNetworkType,
            Name = vSwitchName,
            Subnets = prefixes.Select((prefix, i) => new HnsSubnet
            {
                AddressPrefix = prefix,
                GatewayAddress = i < gateways.Length && !string.IsNullOrEmpty(gateways[i]) ? gateways[i] : null
            }).ToList()
        };

        var jsonString = JsonSerializer.Serialize(hnsNetwork, HnsJsonContext.Default.HnsNetworkRequest);
        if (_logger.IsEnabled(LogLevel.Information))
            _logger.LogInformation("Creating HNS network object: {JsonString}", jsonString);

        HNSCall("POST", "/networks", jsonString, out string response);
        if (_logger.IsEnabled(LogLevel.Information))
            _logger.LogInformation("HNS network object creation response: {Response}", response);

        var match = HNSSuccessRegex().Match(response);
        var success = match.Success && bool.Parse(match.Groups[1].Value);

        if (!success)
        {
            _logger.LogError("Failed to create HNS network object");
            if (_shutdownOnCriticalFailure)
            {
                _logger.LogError("ShutdownOnCriticalFailure is enabled - initiating immediate system shutdown.");
                Process.Start("shutdown.exe", "/s /t 0 /c \"EKS Bootstrapper: HNS network creation failed\"");
                return;
            }
            throw new Exception("Failed to create HNS network object");
        }

        _logger.LogInformation("HNS network object created successfully");
        await AddRoutesTovNIC(cancellationToken);
    }

    async Task AddRoutesTovNIC(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Looking for vNIC with Name 'vEthernet*' to add routes");
        var timeout = TimeSpan.FromSeconds(10);
        var interval = TimeSpan.FromMilliseconds(200);
        var stopwatch = Stopwatch.StartNew();
        NetworkInterface? vNIC = null;

        while (stopwatch.Elapsed < timeout)
        {
            try
            {
                vNIC = NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(ni => ni.Name.StartsWith("vEthernet"));
                if (vNIC != null) break;
                if (_logger.IsEnabled(LogLevel.Information))
                    _logger.LogInformation("vNIC for ENI 'vEthernet*' is not available yet to add routes. Time elapsed: {ElapsedMs} ms", stopwatch.ElapsedMilliseconds);
                await Task.Delay(interval, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error while looking for vNIC with Name 'vEthernet*' to add routes");
            }
        }

        if (vNIC == null)
        {
            _logger.LogInformation("vNIC for ENI 'vEthernet*' is not available yet to add routes.");
            return;
        }

        var vNICIndex = vNIC.GetIPProperties().GetIPv4Properties().Index;

        var routeAddCommands = new StringBuilder();
        for (int i = 0; i < MetadataRouteAddresses.Length; i++)
        {
            routeAddCommands.Append($"route ADD {MetadataRouteAddresses[i]} MASK 255.255.255.255 0.0.0.0 IF {vNICIndex}");
            if (i < MetadataRouteAddresses.Length - 1)
            {
                routeAddCommands.Append(" & ");
            }
        }

        // Execute the route add commands using System.Diagnostics.Process
        Process process = new();
        process.StartInfo.FileName = "cmd.exe";
        process.StartInfo.Arguments = $"/C {routeAddCommands}";
        process.StartInfo.RedirectStandardOutput = true;
        process.StartInfo.UseShellExecute = false;
        process.StartInfo.CreateNoWindow = true;
        process.Start();
        await process.WaitForExitAsync(cancellationToken);
        if (_logger.IsEnabled(LogLevel.Information))
        {
            _logger.LogInformation("Added routes to vNIC: {VNICName}", vNIC.Name);
            _logger.LogInformation("Route add commands: {RouteAddCommands}", routeAddCommands);
            _logger.LogInformation("Route add command output: {Output}", process.StandardOutput.ReadToEnd());
        }
    }
}

public class HnsNetworkRequest
{
    public required string Type { get; set; }
    public string? Name { get; set; }
    public List<HnsSubnet>? Subnets { get; set; }
}

public class HnsSubnet
{
    public required string AddressPrefix { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? GatewayAddress { get; set; }
}

[JsonSerializable(typeof(HnsNetworkRequest))]
public partial class HnsJsonContext : JsonSerializerContext
{
}

// CNI and kubelet config DTOs for safe JSON serialization (no string interpolation)
public class CniConfig
{
    public string CniVersion { get; set; } = "";
    public string Name { get; set; } = "";
    public string Type { get; set; } = "";
    public CniCapabilities? Capabilities { get; set; }
    public bool DisableCheck { get; set; }
    public string EniMACAddress { get; set; } = "";
    public string[] EniIPAddresses { get; set; } = [];
    public string? GatewayIPAddress { get; set; }
    public List<string> VpcCIDRs { get; set; } = [];
    public string ServiceCIDR { get; set; } = "";
    public CniDnsConfig? Dns { get; set; }
}

public class CniCapabilities
{
    public bool PortMappings { get; set; }
}

public class CniDnsConfig
{
    public string[] Nameservers { get; set; } = [];
    public string[] Search { get; set; } = [];
}

public class KubeletConfiguration
{
    public string Kind { get; set; } = "";
    public string ApiVersion { get; set; } = "";
    public string Address { get; set; } = "";
    public KubeletAuthentication? Authentication { get; set; }
    public KubeletAuthorization? Authorization { get; set; }
    public string ClusterDomain { get; set; } = "";
    public string HairpinMode { get; set; } = "";
    public string CgroupDriver { get; set; } = "";
    public string CgroupRoot { get; set; } = "";
    public Dictionary<string, bool>? FeatureGates { get; set; }
    public bool SerializeImagePulls { get; set; }
    public bool ServerTLSBootstrap { get; set; }
    public string[]? ClusterDNS { get; set; }
}

public class KubeletAuthentication
{
    public KubeletAnonymous? Anonymous { get; set; }
    public KubeletWebhook? Webhook { get; set; }
    public KubeletX509? X509 { get; set; }
}

public class KubeletAnonymous
{
    public bool Enabled { get; set; }
}

public class KubeletWebhook
{
    public string CacheTTL { get; set; } = "";
    public bool Enabled { get; set; }
}

public class KubeletX509
{
    public string? ClientCAFile { get; set; }
}

public class KubeletAuthorization
{
    public string Mode { get; set; } = "";
    public KubeletAuthWebhook? Webhook { get; set; }
}

public class KubeletAuthWebhook
{
    public string CacheAuthorizedTTL { get; set; } = "";
    public string CacheUnauthorizedTTL { get; set; } = "";
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(CniConfig))]
[JsonSerializable(typeof(CniDnsConfig))]
[JsonSerializable(typeof(CniCapabilities))]
[JsonSerializable(typeof(KubeletConfiguration))]
[JsonSerializable(typeof(KubeletAuthentication))]
[JsonSerializable(typeof(KubeletAnonymous))]
[JsonSerializable(typeof(KubeletWebhook))]
[JsonSerializable(typeof(KubeletX509))]
[JsonSerializable(typeof(KubeletAuthorization))]
[JsonSerializable(typeof(KubeletAuthWebhook))]
[JsonSerializable(typeof(Dictionary<string, bool>))]
public partial class BootstrapperJsonContext : JsonSerializerContext
{
}