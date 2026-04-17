---
mode: agent
description: 新しい外部 API ラッパーツール (src/tools/<service>.py) を雛形から生成する
---

新しい外部 API ラッパーツールを追加してください。

**サービス名**: ${input:service:サービス名 (snake_case, 例: greynoise, abuseipdb, crtsh)}
**公式 API ドキュメント URL**: ${input:api_docs:公式ドキュメントの URL}
**認証**: ${input:auth:none / api_key / oauth}
**実装したいアクション (複数可、カンマ区切り)**: ${input:actions:例: classify_ip, reputation_lookup}

## 要件

1. `.github/instructions/tool-module.instructions.md` に従った構造で `src/tools/${input:service}.py` を生成する
2. 各アクションごとに以下を実装:
   - Pydantic レスポンスモデル
   - Pure async helper 関数
   - FastAPI エンドポイント (`summary`, `description`, `examples` 付き)
   - `@mcp.tool()` でラップした MCP 関数
3. `src/app.py` にインポートと `include_router` + `register_mcp_tools` を 2 行追加
4. `tests/test_app.py` の `test_openapi_schema_contains_tools` に新エンドポイントパスを追加
5. `README.md` の「What's inside」テーブルに行を追加
6. 認証が必要な場合は環境変数 `${input:service|upper}_AUTH_KEY` または `_API_KEY` を導入し:
   - `src/tools/${input:service}.py` で未設定時に 503 を返す
   - `deploy/main.bicep` に `@secure()` パラメータ、secret、env を追加
   - `deploy/parameters.example.json` に空値で追加
   - README の「Optional environment variables」に追記

## 実装後

- `ruff check .` と `pytest -q` を実行してクリーンであることを確認
- curl でライブ API を 1 件だけ叩いてスモークテスト結果を示す
- Conventional Commits で `feat(${input:service}): add <actions> tools` として英語でコミット

## 参考実装

- `src/tools/kev.py` (認証不要の典型例)
- `src/tools/abusech.py` (認証必須 + 複数エンドポイントの典型例)
