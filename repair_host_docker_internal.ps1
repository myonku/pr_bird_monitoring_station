param(
    [string]$HostsFile = "$env:WINDIR\System32\drivers\etc\hosts",
    [string]$Hostname = "host.docker.internal"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Get-PrimaryIpv4Address {
    $route = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -AddressFamily IPv4 |
        Sort-Object RouteMetric, InterfaceMetric |
        Select-Object -First 1

    if (-not $route) {
        throw "Unable to locate the primary IPv4 route."
    }

    $address = Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $route.ifIndex |
        Where-Object {
            $_.IPAddress -ne "127.0.0.1" -and
            $_.IPAddress -notlike "169.254.*"
        } |
        Select-Object -First 1

    if (-not $address) {
        throw "Unable to determine the primary IPv4 address."
    }

    return $address.IPAddress
}

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    throw "Run this script in an elevated PowerShell session."
}

$currentIp = Get-PrimaryIpv4Address
$lines = Get-Content -Path $HostsFile
$pattern = "^\s*[\d\.]+\s+$([regex]::Escape($Hostname))(\s+.*)?$"
$replacement = "$currentIp $Hostname"
$updated = $false
$output = New-Object System.Collections.Generic.List[string]

foreach ($line in $lines) {
    if ($line -match $pattern) {
        if (-not $updated) {
            $output.Add($replacement)
            $updated = $true
        }

        continue
    }

    $output.Add($line)
}

if (-not $updated) {
    $output.Add($replacement)
}

Set-Content -Path $HostsFile -Value $output -Encoding ASCII -Force

if (Get-Command Clear-DnsClientCache -ErrorAction SilentlyContinue) {
    Clear-DnsClientCache
}

Write-Host "Updated $Hostname to $currentIp in $HostsFile"