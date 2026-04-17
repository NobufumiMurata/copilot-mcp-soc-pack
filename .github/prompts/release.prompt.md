---
mode: agent
description: master ブランチで新しいリリース (semver タグ) を打ち GHCR にイメージを公開する
---

新しいリリースを作成してください。

**リリースバージョン**: ${input:version:semver (例: v0.2.0)}
**主な変更点の一行サマリ**: ${input:summary:例: "Add Abuse.ch Pack (MalwareBazaar, ThreatFox, URLhaus)"}

## 手順

1. 現在のブランチが `master` かつクリーンであることを確認
2. 最新を pull (`git pull --ff-only`)
3. `ruff check .` と `pytest -q` がグリーンであることを確認
4. `README.md` の Roadmap 該当項目にチェックを入れる
5. コミット (`docs: mark ${input:version} roadmap item complete`)
6. `git tag -a ${input:version} -m "${input:version} - ${input:summary}"` でタグ作成
7. `git push origin master --tags` で push
8. `gh release create ${input:version} --generate-notes` で Release を作成
9. GHCR ワークフロー (`build-push.yml`) の完了を確認し、`ghcr.io/nobufumimurata/copilot-mcp-soc-pack:${input:version}` が pull できることを確認:
   ```powershell
   docker pull ghcr.io/nobufumimurata/copilot-mcp-soc-pack:${input:version}
   ```

## 注意

- タグは semver 厳守 (`vMAJOR.MINOR.PATCH`)
- メジャー (v1.0.0) のみ Release notes を手動で整える。マイナー/パッチは `--generate-notes` 任せで良い
- 破壊的変更があるときはメジャーを上げる (v1.x → v2.x)
