---
description: Azure Container Apps に現行 master をデプロイし、Security Copilot から呼び出すまでをガイド
mode: agent
---

現在の master を Azure Container Apps にデプロイし、Security Copilot に登録するまでをサポートしてください。

**リソースグループ名**: ${input:rg:リソースグループ名 (例: rg-copilot-mcp-soc-pack-test)}
**リージョン**: ${input:region:例: japaneast, westus2}
**API キー**: ${input:api_key:Security Copilot が X-API-Key ヘッダーで送る共有シークレット。空ならランダム生成}
**abuse.ch Auth-Key**: ${input:abuse_key:optional, 空なら /abusech/* エンドポイントは 503 を返す}

## 手順

### 1. Azure CLI の前提確認

```powershell
az account show | Select-Object name, user
az provider register -n Microsoft.App
az provider register -n Microsoft.OperationalInsights
```

### 2. リソースグループ作成

```powershell
az group create -n ${input:rg} -l ${input:region} --tags project=copilot-mcp-soc-pack
```

### 3. Deploy to Azure ボタン動作確認 (任意)

README の Deploy to Azure ボタンをブラウザで開き、上記と同じ RG に対してポータルからデプロイしても良い。CLI で完結させる場合は次ステップ。

### 4. Bicep デプロイ

```powershell
cd d:\VSCodeWorkspaces\copilot-mcp-soc-pack
az deployment group create `
  --resource-group ${input:rg} `
  --template-file deploy/main.bicep `
  --parameters `
    containerAppName=copilot-mcp-soc-pack `
    apiKey='${input:api_key}' `
    abuseChAuthKey='${input:abuse_key}' `
  --query 'properties.outputs'
```

### 5. FQDN と疎通確認

```powershell
$fqdn = az containerapp show -n copilot-mcp-soc-pack -g ${input:rg} --query 'properties.configuration.ingress.fqdn' -o tsv
Invoke-RestMethod "https://$fqdn/health"
Invoke-RestMethod "https://$fqdn/kev/lookup?cve_id=CVE-2024-3400" -Headers @{ 'X-API-Key' = '${input:api_key}' }
```

### 6. Security Copilot への登録

1. <https://securitycopilot.microsoft.com/> にサインイン (Copilot owner ロール必要)
2. プラグインアイコン (コンセント) → Custom plugins → Add plugin → API
3. **Schema URL**: `https://$fqdn/openapi.json`
4. **Auth**: API Key (Header), name `X-API-Key`, value = 上記 API キー
5. プラグインを有効化し、プロンプト例: "Using the SOC Pack, list CISA KEV entries added in the last 7 days."

### 7. エージェント登録 (任意)

`sc-plugin/agent.yaml` をダウンロードして Build → My agents → Upload YAML。

### 8. コスト確認

```powershell
az consumption usage list --start-date (Get-Date).AddDays(-1).ToString('yyyy-MM-dd') --end-date (Get-Date).ToString('yyyy-MM-dd') | ConvertFrom-Json | Where-Object { $_.instanceName -like '*copilot-mcp-soc-pack*' }
```

scale-to-zero により非アクティブ時は課金されないことを確認する。

### 9. クリーンアップ (検証用環境の場合)

```powershell
az group delete -n ${input:rg} --yes --no-wait
```
