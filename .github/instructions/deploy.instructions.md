---
applyTo: "deploy/**"
---

# Bicep / ARM Instructions

## Source of Truth

- **`deploy/main.bicep` のみが source of truth**
- `deploy/azuredeploy.json` は `bicep-build.yml` ワークフローが自動生成・自動コミット。**手動編集禁止**
- ローカルで試した場合は `az bicep build --file deploy/main.bicep --outfile deploy/azuredeploy.json` で再生成する

## Container Apps

- `minReplicas: 0` (scale-to-zero) を既定維持
- Liveness/Readiness プローブは `/health` にだけ設定 (アプリ側の responsibility)
- リージョン固有機能 (Azure AD Workload Identity Federation 等) は避ける

## 新しい環境変数 / secret の追加

1. `main.bicep` の `@description @secure() param` を追加
2. `secrets` 配列に `concat()` で追加 (空文字の場合は追加しない)
3. container の `env` に `secretRef` を追加 (同じく `concat()`)
4. `parameters.example.json` にも空値で追加
5. README の「Optional environment variables」テーブルに追記
6. 対応する Python 側コード (`os.environ.get(<VAR>)`) で空/未設定を明示的に扱う

## デプロイパラメータ命名

- camelCase (Bicep convention)
- 対応する環境変数は SCREAMING_SNAKE_CASE (`apiKey` → `MCP_SOC_PACK_API_KEY`)
