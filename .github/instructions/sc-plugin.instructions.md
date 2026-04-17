---
applyTo: "sc-plugin/**"
---

# Security Copilot Plugin / Agent Instructions

## ファイル構成

- `sc-plugin/ai-plugin.json` — OpenAI plugin manifest (JSON; this is what SC's *OpenAI plugin* uploader consumes)
- `sc-plugin/manifest.yaml` — YAML mirror of the above for human readability (keep both in sync)
- `sc-plugin/agent.yaml` — カスタムエージェント定義 (SC の Build → My agents からアップロード)

## マニフェストの更新

新しい REST エンドポイントを追加しても、マニフェストの `paths` は基本的に空のままで良い (SC は `/openapi.json` を直接読むため)。**変更が必要なのは以下のみ**:

- `info.version` を semver で上げる
- `servers[0].url` のプレースホルダ文言 (`REPLACE-ME.azurecontainerapps.io`)
- `security` / `components.securitySchemes` (認証方式を変える場合のみ)

## Agent YAML の記述ガイドライン

### 英語で書く

エージェントの `instructions` は **必ず英語**。理由:

- Security Copilot の基盤モデルは英語での ATT&CK / KEV / CVE の知識が圧倒的に豊富
- SOC のグローバルユーザーに配布する OSS として英語が標準

### instructions の書き方

- 手順を箇条書きで明示する (ステップ 1, 2, 3)
- 各ステップでどのツール (`kev_lookup` 等) を呼ぶかを指定する
- 出力フォーマットを最後に明記 (テーブル、JSON、Markdown 等)
- **ハルシネーション防止文言**: "Do not invent information that the tools did not return."

### plugins 参照

- `plugins[].name` はプラグインマニフェストの `info.title` ではなく **プラグイン登録時に SC が割り当てる名前** と一致させる
- `skills` リストには agent が使う MCP / OpenAPI ツール名を列挙

## v0.1 の雛形エージェント

- `Vulnerability Triage Agent` — CVE リストを受け取り KEV/EPSS/ATT&CK でスコアリング
- Phase 2.5 で実機検証、追加エージェントは `agents/` サブフォルダに展開予定
