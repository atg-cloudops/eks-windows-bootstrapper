# Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Amazon Software License (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
# http://aws.amazon.com/asl/
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.

<#
.SYNOPSIS
EKS bootstrap script. Should maintain close parity with https://github.com/awslabs/amazon-eks-ami/blob/master/files/bootstrap.sh
.PARAMETER EKSClusterName
Specifies the EKS cluster name which this worker node to be joined.
.PARAMETER KubeletExtraArgs
Specifies the extra arguments for kubelet(optional).
.PARAMETER KubeProxyExtraArgs
Specifies the extra arguments for kube-proxy(optional).
.PARAMETER Endpoint
Specifies the EKS cluster endpoint(optional). Default is production endpoint.
.PARAMETER APIServerEndpoint
The EKS cluster API Server endpoint(optional). Only valid when used with -Base64ClusterCA. Bypasses calling "Get-EKSCluster".
.PARAMETER Base64ClusterCA
The base64 encoded cluster CA content(optional). Only valid when used with -APIServerEndpoint. Bypasses calling "Get-EKSCluster".
.PARAMETER DNSClusterIP
Overrides the IP address to use for DNS queries within the cluster(optional). Defaults to 10.100.0.10 or 172.20.0.10 based on the IP address of the primary interface.
.PARAMETER ServiceCIDR
Overrides the Kubernetes Service IP Address range from which cluster services are addressed. Defaults to 172.20.0.0/16 or 10.100.0.0/16 based on the IP address of the primary interface.
.PARAMETER ExcludedSnatCIDRs
Adds additional CIDRs which should be excluded from SNAT rule. By default, only the VPC CIDR of primary interface is excluded from SNAT rule.
.PARAMETER ContainerRuntime
Specifies the container runtime to be used. On EKS 1.21 and below, it defaults to 'docker'. On EKS 1.24 and above, defaults to 'containerd'.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [string]$EKSClusterName,
  [string]$KubeletExtraArgs,
  [string]$KubeProxyExtraArgs,
  [string]$Endpoint,
  [string]$APIServerEndpoint,
  [string]$Base64ClusterCA,
  [string]$DNSClusterIP,
  [string]$ServiceCIDR,
  [string[]]$ExcludedSnatCIDRs,

  [ValidateSet("docker","containerd")]
  [string]$ContainerRuntime
)

$ErrorActionPreference = 'STOP'
