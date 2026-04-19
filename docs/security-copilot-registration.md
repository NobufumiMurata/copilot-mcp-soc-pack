# Security Copilot registration runbook

This runbook walks a Security Copilot **Owner** (or Contributor with the
"add custom plugins" permission enabled) through registering the SOC Pack
plugin and the three reference agents against an already-deployed Container
App.

> Prerequisite: the Container App is up and reachable at an HTTPS FQDN, and
> you already know the `X-API-Key` value generated at deployment time. If
> you followed the `Deploy to Azure` button in the main README, the key is
> stored as the `api-key` secret of the Container App and passed to the
> runtime via the `MCP_SOC_PACK_API_KEY` environment variable.

## 0. Smoke-test the endpoint first

Before touching Security Copilot, confirm the Container App actually serves
an OpenAPI 3.0.1 document and honours the API key:

```bash
curl -s "https://<your-fqdn>/openapi.json" | jq -r '.openapi, (.paths | length)'
# -> 3.0.1
# -> 19  (or whatever the current tool count is)

curl -s -o /dev/null -w "%{http_code}\n" \
  -H "X-API-Key: <your-key>" \
  "https://<your-fqdn>/kev/lookup?cve_id=CVE-2024-3400"
# -> 200

curl -s -o /dev/null -w "%{http_code}\n" \
  "https://<your-fqdn>/kev/lookup?cve_id=CVE-2024-3400"
# -> 401
```

If any of the above does not match, fix the deployment before continuing.

## 1. Confirm plugin-management permissions (Owner only)

1. Sign in to <https://securitycopilot.microsoft.com> as an Owner.
2. Left nav: **Owner** -> **Plugin settings**.
3. Under "Who can add and manage custom plugins for themselves" pick
   **Owners and Contributors** if you want teammates to be able to add the
   plugin for their own sessions. Otherwise leave it at **Owners only**.
4. Under "Who can add and manage custom plugins for everyone in the
   organization?" keep the default (**Owners only**) unless you explicitly
   want to publish tenant-wide.

## 2. Register the plugin

1. Left nav: **Sources** (the plug icon).
2. Scroll to the **Custom** section at the bottom.
3. Click **Upload plugin**.
4. In the dialog:
   - **Availability**: `Just me` for the first round of testing. Switch to
     `Anyone in the organization` once you are happy with behaviour.
   - **Plugin type**: choose **Security Copilot plugin** — *not* "OpenAI
     plugin". Security Copilot's OpenAI-plugin loader does not yet support
     shared-secret authentication, so the native Descriptor + SkillGroups
     manifest in this repo is the supported path.
5. Provide the manifest. Either option works:
   - **Upload as link**: paste the raw GitHub URL of
     [`sc-plugin/manifest.yaml`](../sc-plugin/manifest.yaml) and select the
     file type `YAML`.
   - **Upload file**: pick the local copy of `sc-plugin/manifest.yaml`.

   > The OpenAI-format mirror at `sc-plugin/ai-plugin.json` is kept for
   > completeness, but Security Copilot rejects its `auth` block today
   > with "Unsupported auth type". Use the YAML manifest instead.
6. Click **Add**.

Security Copilot will fetch the manifest, follow `OpenApiSpecUrl` to
download the OpenAPI spec, and prompt you to configure the `X-API-Key`
header value (declared via `Authorization.Type: APIKey` in the manifest).

## 3. Configure the API key

1. In the plugin setup panel, paste the shared API key you set when
   deploying the Container App (`$env:MCP_API_KEY` in the deployment
   runbook) into the **X-API-Key** field.
2. Click **Setup** / **Save**.

The plugin will appear in the **Custom** section of the Sources panel with
a toggle. Make sure the toggle is **On**.

## 4. Verify with a probe prompt

Open a fresh Security Copilot session and run:

```
Is CVE-2024-3400 in the CISA KEV catalog, and what is its EPSS score?
```

Expected behaviour:
- Security Copilot calls `kev_lookup` and `epss_score` from the plugin.
- The reply cites CISA KEV (Palo Alto Networks PAN-OS) and an EPSS number.
- The session header shows **Chose Copilot MCP SOC Pack** with a green
  check, followed by *Processed your request* and *Prepared your response*.

> **Cold-start note**: the Container App ships with `minReplicas: 0`
> (scale-to-zero, ~$0/month idle). The first prompt after a quiet period
> can take 10–25 seconds while the replica wakes up. Subsequent prompts
> respond in 1–3 seconds. If you want guaranteed sub-second responses,
> set `--min-replicas 1` (≈ $15/month).

If instead you see a skill-call error, open the prompt's execution trace
and look at the raw HTTP response; the most common failures are:

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| "Your role doesn't have access to that information" | API key not configured during plugin setup | Sources -> Custom -> gear icon -> re-enter `X-API-Key` |
| Plugin upload times out (~20s) | First call hit a cold replica | Warm with `curl https://<fqdn>/health` then re-upload |
| 503 Service Unavailable on abuse.ch / GreyNoise / AbuseIPDB skills | External API key secret not set in Container App | Add the secret via `az containerapp secret set` and update the env var |
| "The plugin couldn't be loaded" / "Unsupported auth type" | Uploaded the OpenAI-format `ai-plugin.json` instead of the native `manifest.yaml` | Re-upload using **Security Copilot plugin** type with `sc-plugin/manifest.yaml` |

## 5. Upload the reference agents (optional)

1. Left nav: **Build** -> **My agents** -> **Upload YAML**.
2. Upload [`sc-plugin/agent.yaml`](../sc-plugin/agent.yaml) or paste the
   raw GitHub URL. The file contains three agents:
   - `Vulnerability Triage Agent (SOC Pack)`
   - `IOC Enrichment Agent (SOC Pack)`
   - `Ransomware Weekly Briefing Agent (SOC Pack)`
3. For each agent, verify that the plugin reference resolves to the
   plugin you registered in step 2 (the name will be
   `Copilot MCP SOC Pack` in the UI).

## 6. Suggested test prompts

### Vulnerability triage

```
Triage these CVEs for P1/P2/P3: CVE-2024-3400, CVE-2024-21762, CVE-2024-6387.
```

### IOC enrichment

```
Enrich these IOCs and tell me which are active threats:
  - 1.1.1.1
  - 8.8.8.8
  - 185.220.101.1
  - evil.example.com
  - 44d88612fea8a8f36de82e1278abb02f
```

### Ransomware briefing

```
Give me the weekly ransomware briefing filtered to Japan.
```

```
Which sectors has LockBit 3.0 hit most often this year?
```

### Subdomain / attack-surface

```
Enumerate the subdomains of contoso.com using Certificate Transparency.
```

### Cross-skill

```
Is the CVE exploited by any ransomware group currently active?
Compare the KEV ransomware flag with the latest ransomware.live group list.
```

## 7. Rotating the shared API key

If you need to rotate the `X-API-Key` value:

```powershell
$newKey = [Convert]::ToBase64String([byte[]](1..32 | % { Get-Random -Max 256 }))
az containerapp secret set -g rg-copilot-mcp-soc-pack-test -n copilot-mcp-soc-pack `
  --secrets api-key=$newKey
az containerapp update -g rg-copilot-mcp-soc-pack-test -n copilot-mcp-soc-pack `
  --set-env-vars MCP_SOC_PACK_API_KEY=secretref:api-key
```

Then in Security Copilot: **Sources** -> **Custom** -> gear icon on
`Copilot MCP SOC Pack` -> **Edit** -> re-enter the new value under
`X-API-Key` -> **Save**. The key is only stored in the plugin's secret
bucket; it is never embedded in the uploaded YAML.

## 8. Removing the plugin

**Sources** -> **Custom** -> gear icon on `Copilot MCP SOC Pack` ->
**Delete** -> confirm. This does not touch the Azure resources; the
Container App keeps running until you delete the resource group.
