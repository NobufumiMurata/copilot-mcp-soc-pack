<#
.SYNOPSIS
  End-to-end smoke test for a deployed Copilot MCP SOC Pack instance.

.DESCRIPTION
  Hits a representative slice of the live API surface and prints a pass/fail
  table. Designed for SOC operators who just deployed (or upgraded) the
  Container App and want a 30-second sanity check before pointing Security
  Copilot at the FQDN.

  All upstream-key-dependent endpoints (abuse.ch, AbuseIPDB, GreyNoise) are
  marked "skip" when the corresponding 503 detail is returned, so this script
  works on minimum-viable deployments too.

.PARAMETER Fqdn
  Container App FQDN, with or without https://. Defaults to the maintainer's
  reference deployment (you almost certainly want to override this).

.PARAMETER ApiKey
  X-API-Key header value. If omitted, the script reads it from the env var
  MCP_API_KEY.

.EXAMPLE
  ./scripts/smoke.ps1 -Fqdn copilot-mcp-soc-pack.salmonsea-6e7f9e16.japaneast.azurecontainerapps.io
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Fqdn,

    [string]$ApiKey = $env:MCP_API_KEY
)

$ErrorActionPreference = 'Stop'

if (-not $ApiKey) {
    Write-Error "ApiKey not provided and `$env:MCP_API_KEY is empty. Pass -ApiKey or set the env var."
    exit 2
}

if ($Fqdn -notmatch '^https?://') { $Fqdn = "https://$Fqdn" }
$base = $Fqdn.TrimEnd('/')
$headers = @{ 'X-API-Key' = $ApiKey }

$probes = @(
    @{ Name = 'health (no auth)';            Path = '/health';                                                  Auth = $false; Expect = 'ok' }
    @{ Name = 'openapi.json (no auth)';      Path = '/openapi.json';                                            Auth = $false; Expect = '3.0.1' }
    @{ Name = 'kev_lookup CVE-2024-3400';    Path = '/kev/lookup?cve_id=CVE-2024-3400';                         Auth = $true  }
    @{ Name = 'epss_score CVE-2024-3400';    Path = '/epss/score?cve_id=CVE-2024-3400';                         Auth = $true  }
    @{ Name = 'attack T1566';                Path = '/attack/technique?technique_id=T1566';                     Auth = $true  }
    @{ Name = 'crtsh example.com';           Path = '/crtsh/subdomains?domain=example.com';                     Auth = $true  }
    @{ Name = 'ransomware_live recent';      Path = '/ransomware/recent?limit=5';                               Auth = $true  }
    @{ Name = 'malwarebazaar recent';        Path = '/abusech/malwarebazaar/recent?window=100&limit=2';         Auth = $true  }
    @{ Name = 'threatfox recent';            Path = '/abusech/threatfox/recent?days=1';                         Auth = $true  }
    @{ Name = 'abuseipdb 1.1.1.1';           Path = '/abuseipdb/check?ip=1.1.1.1';                              Auth = $true  }
    @{ Name = 'greynoise 8.8.8.8';           Path = '/greynoise/classify?ip=8.8.8.8';                           Auth = $true  }
    @{ Name = 'otx ipv4 8.8.8.8';            Path = '/otx/ipv4?ip=8.8.8.8';                                     Auth = $true  }
    @{ Name = 'hibp breaches adobe.com';     Path = '/hibp/breaches_by_domain?domain=adobe.com';                Auth = $true  }
)

$results = foreach ($p in $probes) {
    $url = "$base$($p.Path)"
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $status = 'PASS'; $code = 0; $detail = ''
    try {
        if ($p.Auth) {
            $r = Invoke-WebRequest -Uri $url -Headers $headers -TimeoutSec 30
        } else {
            $r = Invoke-WebRequest -Uri $url -TimeoutSec 30
        }
        $code = [int]$r.StatusCode
        if ($p.Expect -and ($r.Content -notmatch [regex]::Escape($p.Expect))) {
            $status = 'FAIL'
            $detail = "expected substring '$($p.Expect)' missing"
        }
    } catch {
        $resp = $_.Exception.Response
        $code = if ($resp) { [int]$resp.StatusCode.value__ } else { 0 }
        if ($code -eq 503) {
            $status = 'SKIP'
            $detail = 'upstream key not configured (503)'
        } else {
            $status = 'FAIL'
            $detail = $_.Exception.Message
        }
    }
    $sw.Stop()
    [pscustomobject]@{
        Probe   = $p.Name
        Status  = $status
        Code    = $code
        Latency = "$($sw.ElapsedMilliseconds)ms"
        Detail  = $detail
    }
}

$results | Format-Table -AutoSize

$failed = @($results | Where-Object Status -eq 'FAIL').Count
$passed = @($results | Where-Object Status -eq 'PASS').Count
$skipped = @($results | Where-Object Status -eq 'SKIP').Count
Write-Host ""
Write-Host "Summary: $passed pass, $skipped skip, $failed fail"
if ($failed -gt 0) { exit 1 }
