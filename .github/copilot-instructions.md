# Copilot Instructions — copilot-mcp-soc-pack

このリポジトリは **Microsoft Security Copilot 向けの OSS MCP サーバー + OpenAPI プラグインバンドル** です。グローバルの SOC チームが Azure ワンクリックで展開できることを最優先にしています。

---

## 1. リポジトリの目的と性質

- **OSS プロジェクト** (MIT ライセンス、public GitHub リポジトリ)
- 主要ユーザーは **英語圏の SOC チーム**。README・公開ドキュメント・コミット・PR・Issue は **英語で記述**
- チャット内での会話は **日本語** で行う (メンテナは日本語話者)
- ラボ固有の情報や機密情報は一切含めない (LabNote リポジトリと完全分離)

## 2. ディレクトリ構造

```text
copilot-mcp-soc-pack/
├── src/
│   ├── app.py                 # FastAPI + fastmcp エントリ
│   ├── common/                # HTTP クライアント、キャッシュ等の共有ユーティリティ
│   └── tools/                 # 1 モジュール = 1 カテゴリの外部 API ラッパー
├── deploy/
│   ├── main.bicep             # Azure Container Apps + LAW
│   └── azuredeploy.json       # bicep build で自動生成 (手動編集禁止)
├── sc-plugin/                 # Security Copilot プラグイン/エージェントマニフェスト
├── mcp-client-config/         # VS Code / Claude Desktop 設定サンプル
├── tests/                     # pytest
└── .github/workflows/         # build-push (GHCR), lint-test, bicep-build
```

## 3. コーディング規約

### 3.1 Python (3.12+)

- **すべての I/O は async** (`httpx.AsyncClient`、`async def` ハンドラ)
- 型ヒント必須。`from __future__ import annotations` は全ファイルの先頭に
- Pydantic v2 モデルで入出力を明示 (`BaseModel`, `model_dump()`)
- 例外は FastAPI の `HTTPException` で統一、モデルのバリデーション失敗は 400 / 外部 API 認証失敗は 401 / レート制限は 429 / 外部 API 到達不能は 503
- ログは標準 `logging`。`print()` 禁止

### 3.2 新しいツール (外部 API) を追加する手順

`src/tools/<service_name>.py` を 1 ファイル追加して以下の 3 段構造を守る:

1. **pure async helper 関数** — 実装はここ 1 箇所だけ。テストはここを直接呼ぶ
2. **FastAPI `router`** — REST 公開 (OpenAPI → Security Copilot プラグイン)
3. **`register_mcp_tools(mcp: FastMCP)` 関数** — `@mcp.tool(...)` で同じ helper を MCP 公開

既存の [src/tools/kev.py](../src/tools/kev.py) を雛形として参考にすること。

追加後は `src/app.py` の **2 行** を編集するだけで公開される:

```python
from src.tools import <new>
app.include_router(<new>.router, dependencies=[Depends(_require_api_key)])
<new>.register_mcp_tools(mcp)
```

### 3.3 ツール命名

- REST パス: `/<service>/<action>` (例: `/kev/lookup`, `/abusech/threatfox/search`)
- MCP ツール名: `<service>_<action>` (snake_case, 例: `kev_lookup`, `threatfox_search`)
- **Security Copilot のエージェントプロンプトでモデルが呼びやすい名前** を優先 — 抽象的な名前より `ransomware_live_victims_by_country` のような具体名が良い

### 3.4 外部 API 呼び出し

- `src/common/http.py` の `get_client()` を使う (プロセス共有 `httpx.AsyncClient` + User-Agent 統一)
- `TTLCache` を使ってレスポンスを必ずキャッシュ (デフォルト TTL は API ごとに設定、公式レート制限の半分以下を目安に)
- API キーは **環境変数** から読む。必須なら未設定時に 503 を返して「どの変数を設定すべきか」をメッセージに含める
- API キー用環境変数名は `<SERVICE>_AUTH_KEY` または `<SERVICE>_API_KEY` で統一 (例: `ABUSE_CH_AUTH_KEY`, `GREYNOISE_API_KEY`)

### 3.5 セキュリティ

- 機密値 (API キー、認証トークン) を **ログに出さない**、エラーメッセージに含めない
- 外部 API から取得した任意文字列を Security Copilot に返す場合、**プロンプトインジェクションを想定してツール出力としてのサニタイズ** を意識する (Markdown 記号のエスケープ等は必要に応じて)
- 依存関係追加は **最小限**。OSS プロジェクトのサプライチェーン攻撃耐性を重視
- 生のリークサイトコンテンツ (ランサム被害データの本体) は扱わない。メタデータのみ

## 4. Infrastructure as Code

### 4.1 Bicep

- `deploy/main.bicep` が唯一の source of truth
- `deploy/azuredeploy.json` は **GitHub Actions (`bicep-build.yml`) が自動生成・コミット** する。**手動で編集しない**
- 新しい Container App 環境変数や secret を追加する際は `main.bicep` の `secrets` と `env` 両方を更新し、README の Optional environment variables テーブルに記載

### 4.2 デプロイ互換性

- Container Apps が提供される **全 Azure リージョン** で動作させる (リージョン固有機能は避ける)
- `minReplicas: 0` (scale-to-zero) を既定維持 — コールドスタート遅延 < 30 秒が目標
- Managed Identity は将来追加するが、現時点では API キー secret のみでシンプルに保つ

## 5. Security Copilot 固有の考慮点

### 5.1 OpenAPI スキーマ

- **Security Copilot は OpenAPI 3.0.1 を要求** する (3.1 は未対応の可能性)。FastAPI の既定は 3.1 なので将来的には変換必要
- 各エンドポイントに `summary` と `description` を必ず付ける (SC がエージェント計画時に読む)
- `examples` を積極的に入れる (SC のプロンプト生成品質に影響)

### 5.2 プラグインマニフェスト / エージェント YAML

- `sc-plugin/manifest.yaml` と `sc-plugin/agent.yaml` は **v0.1 では雛形**。Phase 2.5 で実機検証後に確定させる
- Agent の `instructions` は日本語で書かず **英語で書く** (モデルの ATT&CK / KEV 知識は英語側が豊富)

## 6. テスト

- `pytest -q` が常にグリーン
- 新しいツールには最低 1 つのテストを追加 (外部 API 呼び出し部分は `httpx.MockTransport` または `pytest-httpx` でモック)
- OpenAPI スキーマに新エンドポイントが含まれることを `tests/test_app.py` の `test_openapi_schema_contains_tools` に追記

## 7. ruff / 型チェック

- `ruff check .` がクリーン
- 行長 100 文字。FastAPI の `Query`/`Depends` は `src/tools/*.py` で B008 除外 (pyproject で設定済み)

## 8. Git / GitHub

- **デフォルトブランチ: `master`**
- コミットメッセージは **英語**。Conventional Commits 推奨:
  - `feat: add greynoise community classifier`
  - `fix(kev): handle missing dateAdded gracefully`
  - `chore: regenerate azuredeploy.json`
  - `docs: update Deploy to Azure instructions`
- PR 説明も英語。スクリーンショット / curl 出力で動作エビデンスを示すこと
- ブランチモデル: 小さな機能は master 直接 push、大きな変更は `feat/*` ブランチから PR

## 9. GHCR / リリース

- `master` への push で `ghcr.io/nobufumimurata/copilot-mcp-soc-pack:latest` と `sha-xxxxxxx` が更新される
- **リリースタグ** (`v0.2.0` など) を push すると semver タグが追加される。タグは semver で `v{major}.{minor}.{patch}`

## 10. よくある落とし穴

- **abuse.ch は Auth-Key 必須** (2024 年以降)。匿名アクセス時は明示的に 503 を返す
- **Bicep の `empty()` は null だけでなく空文字列もカバー** する。`@secure()` パラメータが空のときの default 処理は `empty()` で判定
- **FastAPI の Query(..., alias="cve") に list[str]** を使うと、`?cve=a&cve=b` 形式でリスト受領可能 (配列ではなく複数クエリパラメータ)
- **FastMCP v3 は `http_app()` が ASGI アプリ** を返す。FastAPI に `app.mount("/mcp", mcp.http_app())` でサブアプリとしてマウントする

## 11. 新しい依存関係を追加する際

- `pyproject.toml` の `dependencies` に追記し、理由をコミットメッセージに含める
- Python 3.12 互換必須。 Rust/C 拡張は wheel が multi-arch (amd64 + arm64) で公開されているかを確認

## 12. このリポジトリで使わないもの

- Azure SDK for Python (Key Vault 連携は Container Apps の secret 機能で完結するため)
- Redis / PostgreSQL 等の外部ストア (v1.0 まではインメモリキャッシュで十分)
- Authlib / MSAL 等の OAuth ライブラリ (v1.0 ではインバウンド認証は API キーのみ)
