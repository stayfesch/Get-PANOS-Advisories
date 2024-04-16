   <#
.SYNOPSIS
    Retrieves security advisories from Palo Alto Networks API.

.DESCRIPTION
    This script retrieves security advisories from the Palo Alto Networks API for the specified PAN-OS version.

.PARAMETER ip
    Private IP-Adress of the PaloAlto firewall that will be queried for it's PAN-OS version using SNMP.
    Firewall must be accessible on UDP 161 and have SNMP V2 enabled for community "public".
    If -ip is specified, -panos will be ignored.

.PARAMETER community
    SNMP community defined on the PaloAlto firewall. Default is "public".
    If -panos is specified, -community will be ignored.

.PARAMETER panos
    The PAN-OS version for which advisories are retrieved.
    If -ip is specified, -panos will be ignored.

.PARAMETER severities
    An array of severity levels to filter the advisories. Options are "HIGH", "CRITICAL", "MEDIUM", "LOW", "NONE".

.PARAMETER sort
    The sorting order for advisories. Options are: "cvss", "doc", "date", "updated". "-" before any option will invert the sorting, e.g. "-cvss"

.PARAMETER advanced
    Return count and CVE-ID as XML. Can be used for PRTG Advanced EXE/Script Sensor.
    Otherwise only the total amount of matched CVE's is returned.

.PARAMETER exclude
    List of CVE-ID's to be excluded.

.EXAMPLE
    .\Get-PANOS-Advisories.ps1 -ip "192.168.0.254" -severities "CRITICAL", "HIGH", "MEDIUM" -advanced
    Will query the PAN-OS version 192.168.0.254 via SNMP and return all CRITICAL, HIGH and MEDIUM advisories as XML.

.EXAMPLE
    .\Get-PANOS-Advisories.ps1 -ip "192.168.0.254"
    Will query the PAN-OS version 192.168.0.254 via SNMP and return the amount of critical and high vulnerabilities.

.EXAMPLE
    .\Get-PANOS-Advisories.ps1 -panos "10.1.11-h4" -severities "MEDIUM", "LOW"
    Will return the amount of vulnerabilities for PAN-OS version 10.1.11-h4 with the severitie MEDIUM or LOW

.NOTES
    Author: Felix Schwärzler
    Date: 15.04.2024
    Version: 1.0
    GitHub: https://github.com/stayfesch/Get-PANOS-Advisories

    Requires SNMP Powershell Module (https://www.powershellgallery.com/packages/SNMP/1.0.0.1)

.LINK
    https://security.paloaltonetworks.com
    https://security.paloaltonetworks.com/api
    https://www.powershellgallery.com/packages/SNMP/1.0.0.1
    https://github.com/stayfesch/Get-PANOS-Advisories
#>

param (
    [string]$ip,
    [string]$community = "public",
    [string]$panos,
    [string[]]$severities = @("HIGH", "CRITICAL"),
    [string]$sort = "-cvss",
    [switch]$advanced,
    [string[]]$exclude = @()
)

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]'Tls11,Tls12'

function Get-URI() {
    $url = "https://security.paloaltonetworks.com/api/v1/products/PAN-OS/$panos/advisories/?sort=$sort"

    $severities | ForEach-Object {
        $url += "&severity=$_"
    }

    return $url
}

function Exit-Error($value, $message, $exitcode) {
    if (-not $advanced) {
        Write-Host "${value}:${message}"
        exit $exitcode
    }

    Write-Host "<prtg>"
    Write-Host "<error>$value</error>"
    Write-Host "<text>$message</text>"
    Write-Host "</prtg>"
    exit $exitcode
}

function Get-Version($ip) {
    Try {
        $version = Get-SnmpData -IP $ip -Community $community -OID .1.3.6.1.4.1.25461.2.1.2.1.1.0 -Version V2 -TimeOut 30 -UDPPort 161
    } catch {
        Exit-Error 2 "Error in SNMPT lookup. Make sure $ip is accessible via UDP 161 verify your SNMP settings (OID: .1.3.6.1.4.1.25461.2.1.2.1.1.0)" 2
    }
    if (-not $version) {
        Exit-Error 2 "Error in SNMPT lookup. Make sure $ip is accessible via UDP 161 verify your SNMP settings (OID: .1.3.6.1.4.1.25461.2.1.2.1.1.0)" 2
    }
    return $version.data
}

if (-not $ip -and -not $panos) {
    Get-Help -Name $MyInvocation.InvocationName -Full
    exit
}

if ($ip) {
    $panos = Get-Version $ip
}

$uri = Get-URI
$response = Invoke-RestMethod -Uri $uri

if ($response.success -ne "True") {
    if ($response.message -eq "Unable to find product.") {
        Write-Host "<prtg><result><channel>Version not in Advisory</channel><value>1</value></result>"
        foreach ($severity in $severities) {
            Write-Host "<result><channel>$severity</channel><value>0</value></result>"
        }
        Write-Host "<text>$($response.message) - Most likely there are no advisories (yet) for your version: $panos.</text></prtg>"
        exit 0
    } else {
        Exit-Error 3 $response.message 3
    }
}

# Output for "normal" EXE/Script Sensor
if (-not $advanced) {
    Write-Host "$($response.data.Count):$($response.data.Count) security advisories found for PAN-OS $panos."
    exit 0
}

# XML Output for Advanced EXE/Script Sensor
$text = ""
Write-Host "<prtg>"
Write-Host "<result><channel>Version not in Advisory</channel><value>0</value></result>"
foreach ($severity in $severities) {
    Write-Host "<result>"
    Write-Host "<channel>$severity</channel>"
    $value = 0

    foreach ($cve in $response.data) {
        if ($cve.CVE_data_meta.ID -in $exclude) {
            continue
        }
        if ($cve.impact.cvss.baseSeverity -eq $severity) {
            $text += "$($cve.CVE_data_meta.ID), "
            $value += 1
        }
    }

    Write-Host "<value>$value</value>"
    Write-Host "</result>"
}

if ($text.Length -gt 2) {
    $text = $text.Substring(0,$text.Length-2)
}

Write-Host "<text>$text</text>"
Write-Host "</prtg>"
exit 0