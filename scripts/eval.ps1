<#
.SYNOPSIS
  Run the structured live evaluation harness against a deployed (or local)
  Copilot MCP SOC Pack instance.

.DESCRIPTION
  Wraps `pytest tests/eval -m eval` so SOC operators don't have to remember
  the marker / env-var contract. Each scenario performs a contract-style
  assertion (HTTP status + response shape) against a single endpoint, and
  scenarios for tools whose upstream key isn't configured on the target are
  auto-skipped.

  Use this alongside `scripts/smoke.ps1`:
    * `smoke.ps1`  - 30 second sanity check, ad-hoc curl-style.
    * `eval.ps1`   - full contract suite, suitable for CI / nightly checks.

.PARAMETER Fqdn
  Container App FQDN with or without scheme (e.g.
  `copilot-mcp-soc-pack.<env>.<region>.azurecontainerapps.io`). The script
  prepends `https://` when no scheme is supplied.

.PARAMETER ApiKey
  X-API-Key header value. If omitted, reads $env:MCP_API_KEY.

.PARAMETER Timeout
  Per-request timeout in seconds. Default: 20.

.PARAMETER PytestArgs
  Extra arguments passed verbatim to pytest (e.g. -k for filtering).

.EXAMPLE
  ./scripts/eval.ps1 -Fqdn copilot-mcp-soc-pack.salmonsea-6e7f9e16.japaneast.azurecontainerapps.io

.EXAMPLE
  ./scripts/eval.ps1 -Fqdn localhost:8080 -PytestArgs '-k', 'kev'
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Fqdn,

    [Parameter(Mandatory = $false)]
    [string]$ApiKey,

    [Parameter(Mandatory = $false)]
    [int]$Timeout = 20,

    [Parameter(Mandatory = $false, ValueFromRemainingArguments = $true)]
    [string[]]$PytestArgs
)

if (-not $ApiKey) { $ApiKey = $env:MCP_API_KEY }

if ($Fqdn -notmatch '^https?://') {
    if ($Fqdn -match '^localhost') {
        $base = "http://$Fqdn"
    } else {
        $base = "https://$Fqdn"
    }
} else {
    $base = $Fqdn.TrimEnd('/')
}

$env:EVAL_TARGET_URL = $base
$env:EVAL_API_KEY = $ApiKey
$env:EVAL_TIMEOUT_SECONDS = "$Timeout"

Write-Host "Running live eval against $base" -ForegroundColor Cyan
$args = @('tests/eval', '-m', 'eval', '-v', '--no-header')
if ($PytestArgs) { $args += $PytestArgs }

& python -m pytest @args
exit $LASTEXITCODE
