<!--
Thanks for the PR! A few quick prompts so reviewers can land it fast.
Keep entries short — bullets are fine.
-->

## Summary

<!-- One or two sentences: what does this PR change and why? -->

## Type of change

- [ ] New tool / upstream API
- [ ] Bug fix
- [ ] Docs / README / CONTRIBUTING
- [ ] Infrastructure (Bicep / GitHub Actions / Dockerfile)
- [ ] Security Copilot plugin manifest (`sc-plugin/`)
- [ ] Refactor / chore

## Checklist

- [ ] `ruff check .` passes
- [ ] `pytest -q` passes
- [ ] New / changed code has tests (mock upstream HTTP — never hit real APIs in CI)
- [ ] No secrets, API keys, or PII in code, fixtures, logs, or commit history
- [ ] Upstream API is **free or has a free tier** and used via its **official documented API** (no scraping, no commercial-only sources)
- [ ] If a new tool: REST route + MCP tool + `#ExamplePrompts` block in the OpenAPI `description`
- [ ] If Bicep changed: edited `deploy/main.bicep` only — `deploy/azuredeploy.json` is auto-regenerated
- [ ] If `sc-plugin/manifest.yaml` changed: validated locally that Security Copilot can still load the plugin

## Evidence

<!--
Paste working evidence: curl output, pytest output, a screenshot of the
Security Copilot agent invoking the new skill, etc.
-->

```text

```

## Related issues

<!-- e.g. Fixes #12, Refs #34 -->
