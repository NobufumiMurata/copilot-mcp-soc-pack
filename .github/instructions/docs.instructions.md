---
applyTo: "**/*.md"
---

# Documentation Instructions

## 言語

- **README.md / CONTRIBUTING.md / 公開ドキュメント / コミット / PR / Issue**: 英語
- **内部メモ (.github/instructions/, .github/prompts/)**: 日本語 OK

## スタイル

- 見出し階層 `#` → `##` → `###` を正しくネスト
- コードブロックには必ず言語指定 (```powershell, ```bash, ```python, ```yaml, ```json, ```bicep)
- テーブルを積極的に使う (構成情報・比較)
- リンクは相対パス優先。絶対 URL は外部リソースのみ

## バッジ

README の Deploy to Azure ボタンは以下の形式を維持:

```markdown
[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FNobufumiMurata%2Fcopilot-mcp-soc-pack%2Fmaster%2Fdeploy%2Fazuredeploy.json)
```

パスは `master` ブランチ + `deploy/azuredeploy.json`。URL エンコードを忘れない。
