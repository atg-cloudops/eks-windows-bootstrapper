# EKS Windows Bootstrapper

The EKS Windows Bootstrapper is a fast and efficient tool for bootstrapping Windows nodes in Amazon Elastic Kubernetes Service (EKS). It is written in C#/.NET and is designed to work seamlessly with Karpenter, a popular Kubernetes node autoscaler.

## Features

- Fast and efficient bootstrapping of Windows nodes in EKS
- Seamless integration with Karpenter for automatic node scaling
- Easy to use and configure

## Installation
Use AWS Image Builder to create a custom AMI with the boostrapper installed. You can use the AMIs in a Karpenter Ec2NodeClass.

```
name: Install EKS Windows Bootstrapper
description: Installs the EKS Windows Bootstrapper on the Windows node
schemaVersion: 1.0

phases:
  - name: build
    steps:
      - name: InstallEksWindowsBootstrapper
        action: ExecutePowerShell
        inputs:
          commands:
            - |
              Invoke-WebRequest -Uri 'https://github.com/atg-cloudops/eks-windows-bootstrapper/releases/download/v1.32.0/Install-Service.ps1' -OutFile 'Install-Service.ps1'; 
              .\Install-Service.ps1; 
              Remove-Item 'Install-Service.ps1';
```
Create a new AWS Image builder component with the above content and apply this component to your AWS EKS Windows node recipe.

The output AMI can be used with karpenter or regular cluster autoscaler. No further setup is needed.

### Update Unattend.xml

Remove all the windows configuration components in the oobeSystem pass in unattend.xml which slow down first boot, so it looks like this:

```
  <settings pass="oobeSystem">
    <component name="Security-Malware-Windows-Defender" ...>
    </component>
  </settings>
```
With these components removed, you will have to ensure your images are set to the right culture/timezone before the AMI is created - Windows won't be reconfigured on first boot.

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
