# copilot-mcp-soc-pack

**Community SOC Pack for Microsoft Security Copilot** — free-API MCP server and OpenAPI plugin that gives your SOC instant context from KEV, EPSS, MITRE ATT&CK, Abuse.ch, GreyNoise, AbuseIPDB, crt.sh, and ransomware.live.

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FNobufumiMurata%2Fcopilot-mcp-soc-pack%2Fmaster%2Fdeploy%2Fazuredeploy.json)

[![Build](https://github.com/NobufumiMurata/copilot-mcp-soc-pack/actions/workflows/build-push.yml/badge.svg)](https://github.com/NobufumiMurata/copilot-mcp-soc-pack/actions/workflows/build-push.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

> **Status**: v0.1 (bootstrap). See [ROADMAP](#roadmap).

## Why this exists

Security Copilot ships with great first-party plugins, but SOC teams still spend time copy-pasting IOCs into VirusTotal, checking KEV catalogs, and tracking ransomware group activity. This project bundles the **free, no-account or single-key** sources that every SOC actually uses into **one container**, exposed as both:

- A **Microsoft Security Copilot custom plugin** (OpenAPI 3.0) — invokable from Security Copilot prompts and agents
- A **Model Context Protocol (MCP) server** — usable from VS Code, Claude Desktop, and any MCP-compatible client

One `Deploy to Azure` click → Container Apps (scale-to-zero, < $5/month idle) → register the plugin in Security Copilot → done.

## What's inside (target v1.0)

| Tool | Source | API Key? | Scope |
|------|--------|----------|-------|
| `kev_lookup` / `kev_search` | [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | No | Actively exploited CVE catalog |
| `epss_score` | [FIRST EPSS API](https://www.first.org/epss/api) | No | Exploit prediction scores |
| `attack_technique` / `attack_search` | [MITRE ATT&CK STIX](https://github.com/mitre/cti) | No | TTP lookup with mitigations |
| `malwarebazaar_lookup` / `_recent` | [abuse.ch MalwareBazaar](https://bazaar.abuse.ch/) | Required (free key from [auth.abuse.ch](https://auth.abuse.ch/)) | Sample/hash lookup + recent submissions |
| `threatfox_recent` / `_search` | [abuse.ch ThreatFox](https://threatfox.abuse.ch/) | Required (same key) | IOC enrichment |
| `urlhaus_lookup_url` / `_host` | [abuse.ch URLhaus](https://urlhaus.abuse.ch/) | Required (same key) | Malicious URL feed |
| `greynoise_classify` | [GreyNoise Community](https://www.greynoise.io/) | Free key | Scanner noise vs. targeted |
| `abuseipdb_check` | [AbuseIPDB](https://www.abuseipdb.com/) | Free key | IP reputation |
| `crtsh_subdomains` | [crt.sh](https://crt.sh/) | No | Certificate transparency |
| `ransomware_live_recent` / `_by_group` / `_by_country` | [ransomware.live](https://www.ransomware.live/) | No | Ransomware victim metadata |

**Currently implemented in v0.3**: KEV + EPSS + ATT&CK (v0.1) · Abuse.ch Pack (v0.2, MalwareBazaar / ThreatFox / URLhaus) · IP & Domain Reputation (v0.3, GreyNoise Community / AbuseIPDB / crt.sh). Remaining tools land in v0.4–v0.6.

### Optional environment variables

| Variable | Used by | Notes |
|----------|---------|-------|
| `MCP_SOC_PACK_API_KEY` | All routes | Shared secret for `X-API-Key` header. Leave unset in dev. |
| `ABUSE_CH_AUTH_KEY` | `/abusech/*` | Free key from <https://auth.abuse.ch/>. Required — abuse.ch rejects anonymous calls with HTTP 401. |
| `GREYNOISE_API_KEY` | `/greynoise/*` | Free Community key from <https://viz.greynoise.io/signup>. Required for GreyNoise classification. |
| `ABUSEIPDB_API_KEY` | `/abuseipdb/*` | Free key from <https://www.abuseipdb.com/register> (1000 req/day). Required for AbuseIPDB checks. |

## Quickstart (local)

```bash
# Requires Python 3.12+
git clone https://github.com/NobufumiMurata/copilot-mcp-soc-pack.git
cd copilot-mcp-soc-pack

python -m venv .venv
# Windows
.venv\Scripts\Activate.ps1
# macOS/Linux
# source .venv/bin/activate

pip install -e .
uvicorn src.app:app --reload --port 8080
```

- OpenAPI docs: <http://localhost:8080/docs>
- MCP SSE endpoint: <http://localhost:8080/mcp/sse>
- Health: <http://localhost:8080/health>

### Try a tool

```bash
curl http://localhost:8080/kev/lookup?cve_id=CVE-2024-3400
```

## Quickstart (Docker)

```bash
docker run --rm -p 8080:8080 ghcr.io/nobufumimurata/copilot-mcp-soc-pack:latest
```

## Azure deployment

Click the **Deploy to Azure** button above. You'll be prompted for:

| Parameter | Description | Default |
|-----------|-------------|---------|
| `containerAppName` | Name for your Container App | `copilot-mcp-soc-pack` |
| `location` | Region | Resource group location |
| `apiKey` | Shared secret that Security Copilot will send in the `X-API-Key` header (leave empty = no auth, do not use in production) | generated |
| `image` | Container image | `ghcr.io/nobufumimurata/copilot-mcp-soc-pack:latest` |

After deployment, copy the Container App FQDN (`https://<name>.<region>.azurecontainerapps.io`) and:

1. In Security Copilot, go to **Sources → Custom → Add plugin**
2. Choose **API** → paste `https://<fqdn>/openapi.yaml` as the manifest URL
3. Set authentication to **API Key (header)**, header name `X-API-Key`, value = the `apiKey` you set
4. Enable the plugin and try a prompt:

   > *What CVEs from CISA KEV were added in the last 30 days that have an EPSS score above 0.5?*

## Using with VS Code / Claude Desktop (MCP)

See [mcp-client-config/](./mcp-client-config/) for ready-to-use configurations.

## Roadmap

- [x] v0.1 Bootstrap — FastAPI + fastmcp scaffold, CISA KEV, EPSS, MITRE ATT&CK, Bicep, Deploy to Azure button
- [x] v0.2 Abuse.ch Pack (MalwareBazaar, ThreatFox, URLhaus)
- [x] v0.3 IP/Domain Reputation (GreyNoise, AbuseIPDB, crt.sh)
- [ ] v0.4 ransomware.live tools
- [ ] v0.5 Security Copilot integration (plugin manifest + reference `agent.yaml`)
- [ ] v0.6 Japanese / English README, polish, v1.0 release

## Contributing

PRs welcome. Please keep the free-API, no-scraping, no-raw-leak-data policy intact. See [CONTRIBUTING](./CONTRIBUTING.md) (TBD).

## License

MIT — see [LICENSE](./LICENSE).

## Disclaimer

This project is independent and not affiliated with Microsoft, Anthropic, or any listed third-party service. Users are responsible for complying with the Terms of Service of every external API consumed.
