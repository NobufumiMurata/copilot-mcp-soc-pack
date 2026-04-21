# Promptbook

A curated set of prompts to validate and demonstrate the SOC Pack tools
from either:

- **Microsoft Security Copilot (SC)** standalone portal — using the
  Custom plugin registered from [`sc-plugin/manifest.yaml`](../sc-plugin/manifest.yaml).
- **MCP-aware agentic clients** — VS Code Copilot Chat in Agent Mode,
  Claude Desktop, Cline, etc., using the configs in
  [`mcp-client-config/`](../mcp-client-config/).

The prompts are split into four tiers:

1. **Single-skill smoke prompts** — one prompt invokes one skill. Used to
   confirm the plugin is registered and the API key works.
2. **Composite prompts (planner-driven)** — one prompt that the SC
   planner is expected to satisfy by chaining multiple skills. SC's
   skill chaining is improving but still inconsistent; if the planner
   skips a step, prefer the *agent-style* version below.
3. **Agent-style step-by-step prompts** — explicit numbered workflows
   that name each skill and the order. This is the most reliable way to
   exercise composite flows from Security Copilot today.
4. **MCP client prompts** — short, intent-only prompts that delegate
   the multi-tool plan to a Claude Sonnet / GPT-4-class client.
   Significantly less prescriptive than Tier 3 and produce better
   triage output in practice (April 2026).

> Composite flow caveat for Security Copilot (observed Apr 2026): SC's
> planner sometimes resolves multi-skill prompts to only the first
> matching skill and stops, especially when the second skill depends
> on a value parsed out of the first skill's free-form output (e.g.
> extracting a CVE id from an OSV summary). Use Tier 3 (deterministic
> chains) or Tier 4 (MCP clients) when you need reliable multi-tool
> behaviour.

---

## Tier 1 — Single-skill smoke prompts

### CISA KEV
```
CVE-2024-3400 は CISA KEV に登録されていますか？dateAdded と
knownRansomwareCampaignUse を教えてください。
```

### FIRST EPSS
```
CVE-2024-21762 の EPSS exploit prediction score を教えてください。
```

### MITRE ATT&CK
```
T1059.001 (PowerShell) の MITRE ATT&CK technique 詳細を教えてください。
```

### MalwareBazaar
```
MalwareBazaar に SHA256 が
44d88612fea8a8f36de82e1278abb02f
で登録されているマルウェアサンプルはありますか？
```

### ThreatFox / URLhaus
```
ThreatFox に IP 185.220.101.1 を IOC として登録している脅威があれば
直近のものを教えてください。
```

### GreyNoise
```
185.220.101.1 は GreyNoise でスキャナノイズに分類されていますか？
```

### AbuseIPDB
```
185.220.101.1 の AbuseIPDB confidence score と直近のレポート件数を
教えてください。
```

### crt.sh
```
example.com のサブドメインを Certificate Transparency ログから
列挙してください。
```

### ransomware.live
```
直近の ransomware.live のリーク被害を 20 件出してください。
```

### AlienVault OTX
```
1.1.1.1 に関する AlienVault OTX のパルス情報を教えてください。
```

### HIBP
```
adobe.com に関連する Have I Been Pwned のブリーチ情報を一覧化してください。
```

### OSV.dev (v0.7)
```
Python の requests ライブラリのバージョン 2.20.0 に既知の脆弱性はありますか？
OSV.dev で確認して、CVE / GHSA ID と severity をリストにしてください。
```

### CIRCL hashlookup (v0.7)
```
このファイルの MD5 が 8ed4b4ed952526d89899e723f3488de4 だったのですが、
NSRL 上で既知の正規ファイルか CIRCL hashlookup で確認してください。
```

### MITRE D3FEND (v0.7)
```
MITRE ATT&CK T1486 (Data Encrypted for Impact) を緩和できる D3FEND
防御技術を一覧化してください。defensive tactic ごとにグルーピングして
表で出力してください。
```

---

## Tier 2 — Composite prompts (planner-driven)

These rely on the SC planner to figure out the chain. Test these to
measure SC's chaining capability; if any fails to chain, fall back to
Tier 3.

### CVE-to-defense (KEV + EPSS + ATT&CK + D3FEND)
```
CVE-2024-3400 について、CISA KEV と EPSS でリスクを評価し、
関連する MITRE ATT&CK technique を特定したうえで、その technique を
緩和できる D3FEND 防御技術を一覧化してください。
```

### Hash triage (CIRCL + MalwareBazaar + OTX)
```
SHA256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
について、まず CIRCL hashlookup で NSRL 既知良性か確認し、known=false なら
abuse.ch MalwareBazaar と AlienVault OTX で追加調査してください。
最後に「whitelist / 既知マルウェア / unknown」の3区分で結論づけてください。
```

### IP triage (GreyNoise + AbuseIPDB + OTX + ThreatFox)
```
185.220.101.1 について GreyNoise / AbuseIPDB / AlienVault OTX / ThreatFox
で総合的に評価してください。スキャナノイズか、悪意あるホストか、
特定のマルウェアファミリと紐づいているかを 1 つの結論に集約してください。
```

### Ransomware sector view (ransomware.live + KEV)
```
直近 30 日間でランサムウェアの被害が多いセクター上位 5 つを ransomware.live
から集計し、KEV にランサムウェア利用フラグが立っている CVE のうち、
それらのセクターで関連が想定されるものを示してください。
```

### Supply chain (OSV + KEV)
```
PyPI の requests==2.20.0 と urllib3==1.24.1 を OSV.dev で照会し、
最も深刻な CVE が CISA KEV に掲載されているかも合わせてチェックしてください。
修正バージョンも提示してください。
```

---

## Tier 3 — Agent-style step-by-step prompts

These spell out each skill explicitly. Use these when Tier 2 prompts
fail to chain. They are also the basis for the reference agents in
[`sc-plugin/agent.yaml`](../sc-plugin/agent.yaml) and the MS-schema
manifest at [`sc-plugin/msschema/manifest.yaml`](../sc-plugin/msschema/manifest.yaml).

> Agent Builder note (Apr 2026): the v0.8 MS-schema manifest at
> [`sc-plugin/msschema/manifest.yaml`](../sc-plugin/msschema/manifest.yaml)
> uploads cleanly via **Build → My agents → Upload YAML** and the
> agents publish & run end-to-end, but the SC standalone planner
> still tends to call only **one** of the declared `ChildSkills` per
> agent invocation. The legacy [`sc-plugin/agent.yaml`](../sc-plugin/agent.yaml)
> remains a useful copy-paste source for `description` /
> `instructions`. For reliable multi-tool runs today, drive the same
> tools via an MCP client — see Tier 4 below and
> [`docs/v0.8-msschema-migration.md`](./v0.8-msschema-migration.md).

### CVE → Defense (deterministic chain)
```
以下の手順で CVE-2024-3400 のレポートを SOC 向けにまとめてください。
スキル名と手順は厳守してください。

1. kev_lookup で CISA KEV 該当性を確認 (dateAdded, knownRansomwareCampaignUse, dueDate を抽出)
2. epss_score で exploit prediction score を取得
3. attack_search で "PAN-OS" を検索して関連する MITRE ATT&CK technique を 3 つまで挙げる
4. 上記で得た technique id それぞれに対し d3fend_defenses_for_attack を呼び、
   defensive tactic ごとに上位 3 件の防御技術を抽出
5. 結果を以下の Markdown 構成で出力:
   - ## Risk: KEV/EPSS の要約
   - ## Mapped ATT&CK techniques: 表
   - ## Recommended D3FEND defenses: tactic ごとの箇条書き
```

### Hash triage (deterministic chain)
```
以下のファイルハッシュを順番に調査してください。各ステップでスキル名を
明示し、判定理由を脚注に残してください。

ハッシュ: SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

1. circl_hashlookup_sha256 で NSRL 該当性を確認
   - known=true なら判定 "whitelist" として終了し、メタデータの製品名を表示
2. known=false なら malwarebazaar_lookup を呼ぶ
   - レコードあれば判定 "known malicious" でファミリ / first_seen / signature を表示
3. それでもヒットしなければ otx_lookup_file を呼び、関連パルスがあれば判定 "suspicious"、
   なければ "unknown" で終了

最終出力は JSON 形式: {"verdict":..., "evidence":[...], "next_action":...}
```

### IP triage (deterministic chain)
```
IP 185.220.101.1 について次の順で実行し、各スキルの返り値を脚注に保持してください。

1. greynoise_classify (classification と noise フラグを取得)
2. abuseipdb_check (confidence score と総レポート数)
3. otx_lookup_ipv4 (パルス数)
4. threatfox_search (IOC 該当の有無)

結果を以下のフォーマットで出力:
- 総合判定: "malicious" / "suspicious" / "benign" / "unknown" のいずれか
- 判定理由: 各スキルからの主要シグナルを箇条書き
- 推奨アクション: 1 行
```

### OSS supply-chain triage (deterministic chain)
```
以下のパッケージリストについて、それぞれ独立した手順で評価してください。

対象:
- PyPI: requests==2.20.0
- PyPI: urllib3==1.24.1

各パッケージで:
1. osv_query_package で脆弱性一覧を取得
2. 取得した CVE の中から最も severity の高いものを 1 つ選び、
   kev_lookup で CISA KEV 該当性を確認
3. epss_score で同 CVE の exploit prediction score を取得

最終的に 1 つの Markdown 表で集約:
| Package | Vulns | Top CVE | Severity | KEV? | EPSS | Suggested upgrade |
```

### Ransomware briefing (composite flow)
```
日本 (country code: JP) における直近 30 日のランサムウェア活動を以下の手順で
要約してください。

1. ransomware_live_by_country で country=JP の被害一覧を取得
2. 被害件数上位 3 グループを抽出し、各グループに対し ransomware_live_by_group
   を呼んで活動傾向を補強
3. ransomware_live_groups で各グループの最終活動日を取得

出力は次の構成:
- ## 概要: 全体件数、ピーク日
- ## Top 3 groups: 表 (Group / Victims in JP / Last activity / Notes)
- ## Notable victims: 5 件 (組織名 / セクター / 公開日 / 短い説明)

データの公開・敏感性に配慮し、claim_url や onion link は出力しないでください。
```

---

## Tier 4 — MCP client prompts

Use these from VS Code Copilot Chat (Agent Mode) or Claude Desktop after
configuring the SOC Pack as an MCP server (see
[`mcp-client-config/`](../mcp-client-config/)). The client LLM (Claude
Sonnet / GPT-4-class) is far more capable at planning multi-tool calls
than the SC standalone planner, so these prompts can be much shorter
and more open-ended than Tier 3.

> Tip: prefix each prompt with `#copilot-mcp-soc-pack` (VS Code) or
> `@copilot-mcp-soc-pack` (Claude Desktop) to scope tool selection to
> this server.

### IP triage (4 sources)
```
#copilot-mcp-soc-pack 185.220.101.1 が悪意あるか調査して。
AbuseIPDB、OTX、ThreatFox 全部当たって、最後に総合判定と
推奨対処を出してください。
```

### CVE triage (KEV + EPSS + ATT&CK + D3FEND)
```
#copilot-mcp-soc-pack CVE-2024-3400 のリスクを評価して。
KEV 該当性、EPSS、関連する MITRE ATT&CK technique、それを緩和できる
D3FEND 防御技術まで一気に調べて、SOC Lead 向けにブリーフィング
形式でまとめてください。
```

### Hash triage (whitelist → malware → community)
```
#copilot-mcp-soc-pack このハッシュを段階的に調査してください。
SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

1. CIRCL hashlookup で NSRL 既知良性か
2. 該当しなければ MalwareBazaar
3. それでもヒットしなければ AlienVault OTX のパルス
4. 結論を JSON で出してください
```

### Supply-chain triage (OSV + KEV)
```
#copilot-mcp-soc-pack 以下の依存に既知脆弱性があるか OSV.dev で確認、
最も深刻な CVE が CISA KEV に載っていないかも見て、修正バージョンを
表形式で出してください。

- pypi: requests==2.20.0
- pypi: urllib3==1.24.1
- npm: lodash@4.17.15
```

### Ransomware briefing (ransomware.live + KEV)
```
#copilot-mcp-soc-pack 直近 30 日のランサムウェア被害から、
攻撃が活発なグループ上位 5 つを ransomware.live で抽出。
それぞれのグループが利用していると CISA KEV に記載のある CVE を
紐付けて、SOC Lead 向けの脅威ブリーフィングを書いてください。
```

### Recursive enrichment (open-ended)
```
#copilot-mcp-soc-pack 以下の IOC バンドルを SOC アナリスト視点で
トリアージしてください。型を自動判別して、利用可能な enrichment ツールを
全部使い、最終的に「優先対応 IOC」と「無視してよい IOC」に仕分けて
ください。

185.220.101.1
example.com
44d88612fea8a8f36de82e1278abb02f
https://urlhaus.abuse.ch/url/recent/
CVE-2024-3400
```

### Domain attack-surface (crt.sh + ThreatFox)
```
#copilot-mcp-soc-pack example.com の証明書透明性ログから
サブドメインを列挙し、その中に ThreatFox に登録されている悪意ある
ホストが含まれているかチェックしてください。
```

---

## SC plugin reload checklist

If you add new skills to the plugin (e.g. a new tool module) **after** SC
already has the plugin registered:

1. Container App は image tag を `:0.x.y` で update するだけで OK (FQDN 不変)
2. Security Copilot 側はスナップショット保持型: **Sources → Custom →
   plugin → Remove → Upload file** で再アップロードしないと新スキルは
   planner から見えない。
3. アップロードは **必ずファイル指定** で行う。`Upload as link` に
   upstream OSS の raw URL を指定すると placeholder のままになる
   (`<YOUR-CONTAINER-APP-FQDN>` を解決できない)。

---

## MCP client reload checklist

If you add new tool modules to the SOC Pack **after** an MCP client
(VS Code, Claude Desktop, …) is already connected:

1. Redeploy the Container App image so the new `@mcp.tool` entries are
   exposed at `/mcp/`.
2. In VS Code Copilot Chat: open the **🔧 tool picker** in the chat
   and click **Refresh tools** on the `copilot-mcp-soc-pack` server,
   or use `Developer: Reload Window`. The MCP client caches the tool
   list per session.
3. In Claude Desktop: fully quit and relaunch the app (the MCP server
   list is loaded once at startup).
4. Re-prompt and check that the new tool name shows up in the tool
   picker before referencing it in a prompt.
