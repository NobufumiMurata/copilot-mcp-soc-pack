# Security Policy

## Supported versions

This project is in **Public Preview**. Only the **latest published release** receives security fixes.

| Version | Status |
|---------|--------|
| `master` (latest commit) | Supported |
| Most recent tagged release (e.g. `v0.5.x`) | Supported |
| Older tagged releases | Not supported — please upgrade |

The published container image is `ghcr.io/nobufumimurata/copilot-mcp-soc-pack`. Pin to a semver tag (`:0.5.0`) in production and upgrade promptly when a new release is cut.

## Reporting a vulnerability

**Please do not file a public GitHub issue for security vulnerabilities.**

Report privately via **GitHub Security Advisories**:

1. Go to <https://github.com/NobufumiMurata/copilot-mcp-soc-pack/security/advisories/new>
2. Fill in the form. Include:
   - A clear description of the issue
   - Steps to reproduce (or proof-of-concept)
   - Affected versions / commits
   - Impact assessment (what an attacker could do)
   - Any suggested mitigation

You should receive an acknowledgement within **5 business days**. We aim to publish a fix and an advisory within **30 days** of confirmation, sooner for actively-exploited issues.

If GitHub Security Advisories are unavailable to you, open a minimal public issue saying *"requesting private security contact"* (no details) and a maintainer will reach out.

## Scope

In scope for security reports:

- The MCP server / FastAPI application in this repository (`src/`)
- The Bicep template and Container Apps deployment (`deploy/`)
- The Security Copilot plugin manifest (`sc-plugin/`)
- The published container image on GHCR
- The CI workflows (`.github/workflows/`)

**Out of scope** (please report to the upstream owner instead):

- Vulnerabilities in the upstream threat-intel APIs themselves (CISA KEV, FIRST EPSS, MITRE ATT&CK, abuse.ch, GreyNoise, AbuseIPDB, crt.sh, ransomware.live, AlienVault OTX, Have I Been Pwned)
- Vulnerabilities in Microsoft Security Copilot or Azure Container Apps
- Issues that require an attacker to already have full control of the deployment's API key or the Azure subscription
- Reports based on outdated container images that have already been patched in a newer release

## Hardening recommendations for operators

The default deployment is intentionally minimal. Production operators should consider:

- **Rotate the `MCP_SOC_PACK_API_KEY`** regularly. It is the only inbound auth.
- **Restrict ingress** with Azure Front Door, an IP allow-list, or a private endpoint.
- **Pin the container image** to a semver tag, never `:latest`, and subscribe to release notifications.
- **Review Container App logs** in Log Analytics for unexpected 401s or 503 spikes.
- **Use a dedicated resource group** so blast radius is contained.
- **Set spending caps** on the Azure subscription and the Log Analytics workspace.

## What this project deliberately does NOT do

- It does **not** scrape ransomware leak-site contents — only metadata via ransomware.live's official v2 API.
- It does **not** ingest or store PII / breached credentials. The HIBP integration only returns public breach metadata via the v3 public endpoints.
- It does **not** require any commercial / paid threat-intel licence.
- It does **not** use Managed Identity for inbound auth (yet) — API key only. Track this in the issues if you need it.

Thanks for helping keep the project safe.
