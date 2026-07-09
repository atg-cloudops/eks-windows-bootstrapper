# EKS Windows Bootstrapper

The EKS Windows Bootstrapper is a fast and efficient tool for bootstrapping Windows nodes in Amazon Elastic Kubernetes Service (EKS). It is written in C#/.NET and is designed to work seamlessly with Karpenter, a popular Kubernetes node autoscaler.

## Features

- Fast and efficient bootstrapping of Windows nodes in EKS
- Seamless integration with Karpenter for automatic node scaling
- Easy to use and configure

## Installation

Use AWS Image Builder to create a custom AMI with the bootstrapper installed. The resulting AMI can be used with Karpenter (`Ec2NodeClass`) or the cluster autoscaler.

Create an Image Builder component with the following content and add it to your EKS Windows node recipe. The install script fails the build if downloads or service registration fail, so a GitHub outage or missing artifact will not produce a broken AMI.

```
name: Install EKS Windows Bootstrapper
description: Installs the EKS Windows Bootstrapper on the Windows node
schemaVersion: 1.0

phases:
  - name: build
    steps:
      - name: InstallEksWindowsBootstrapper
        action: ExecutePowerShell
        onFailure: Abort
        inputs:
          commands:
            - |
              $ErrorActionPreference = 'Stop'
              $ReleaseUrl = 'https://github.com/atg-cloudops/eks-windows-bootstrapper/releases/download/v1.36.0'
              Invoke-WebRequest -Uri "$ReleaseUrl/Install-Service.ps1" -OutFile 'Install-Service.ps1' -UseBasicParsing
              .\Install-Service.ps1 -ReleaseUrl $ReleaseUrl -ShutdownOnCriticalFailure
              Remove-Item 'Install-Service.ps1'
```

Update the `$ReleaseUrl` version when you adopt a newer bootstrapper release. No further node setup is required after the AMI is built.

### Update Unattend.xml

Remove all the windows configuration components in the oobeSystem pass in unattend.xml which slow down first boot, so it looks like this:

```
  <settings pass="oobeSystem">
    <component name="Security-Malware-Windows-Defender" ...>
    </component>
  </settings>
```
With these components removed, you will have to ensure your images are set to the right culture/timezone before the AMI is created - Windows won't be reconfigured on first boot.

### Auto Shutdown on Failure

By default, if the bootstrapper encounters a critical failure (e.g. HNS network creation fails), it will throw an exception and the node will be left in a broken state in the cluster.

Enabling `ShutdownOnCriticalFailure` causes the node to immediately shut itself down on a critical failure instead. When using Karpenter, this is the recommended setting — Karpenter's default behaviour is to delete and recreate a node if the underlying instance is shut down, which effectively gives the bootstrap process another attempt on a fresh node.

The Image Builder example above enables this with `-ShutdownOnCriticalFailure`. If you run the install script manually:

```
.\Install-Service.ps1 -ShutdownOnCriticalFailure
```

Alternatively, set `ShutdownOnCriticalFailure` to `"true"` in `appsettings.json`:

```json
{
    "ShutdownOnCriticalFailure": "true"
}
```


#### View Logs
If you have access to the node, you can view the boostrapper logs with (in powershell):
```
get-eventlog Application -Source EKS* | fl
```
## Prerequisites

Before using the EKS Windows Bootstrapper, make sure you have the following prerequisites installed:

- .NET SDK (version 8 or higher)
- Visual Studio 2022, including the Desktop development with C++ workload with all default components.

## Getting Started

To get started with the EKS Windows Bootstrapper, follow these steps:

1. Clone the repository:

    ```shell
    git clone https://github.com/atg-cloudops/eks-windows-bootstrapper.git
    ```

2. Navigate to the project directory:

    ```shell
    cd eks-windows-bootstrapper
    ```

3. Build the project:

    ```shell
    dotnet build
    ```

For more detailed instructions and advanced usage, please refer to the [documentation](https://github.com/atg-cloudops/eks-windows-bootstrapper/wiki).

## Contributing

Contributions are welcome! If you find any issues or have suggestions for improvements, please open an issue or submit a pull request on the [GitHub repository](https://github.com/atg-cloudops/eks-windows-bootstrapper).

## License

This project is licensed under the [MIT License](https://opensource.org/license/mit).
