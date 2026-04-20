# Configure GitHub branch protection for `master`.
#
# Run this once after enabling Public Preview to enforce:
#   - All changes go through a Pull Request (no direct push to master).
#   - Required status checks (lint-test, bicep-build) must pass before merge.
#   - Linear history (squash merge keeps history clean).
#
# Requires GitHub CLI (gh) authenticated with `repo` scope.
# Usage:
#   ./scripts/setup-branch-protection.ps1
#   ./scripts/setup-branch-protection.ps1 -Owner NobufumiMurata -Repo copilot-mcp-soc-pack
#
# Re-run idempotently to update the policy.

[CmdletBinding()]
param(
    [string]$Owner = "NobufumiMurata",
    [string]$Repo = "copilot-mcp-soc-pack",
    [string]$Branch = "master"
)

$ErrorActionPreference = "Stop"

# Required status checks. Names must match the `name:` field of each workflow job
# (as displayed in the GitHub Checks tab on a PR).
#
# Notes:
#   - `test`  -> .github/workflows/lint-test.yml job (ruff + mypy + pytest). Always required.
#   - `bicep-build` is intentionally NOT required because it has path filters on
#     `deploy/main.bicep` and would never run (and therefore never pass) for PRs
#     that do not touch Bicep, blocking merge forever.
#   - `build-push` (image build) is also not required because it pushes to GHCR
#     and is best run AFTER merge to master via tag.
$requiredChecks = @("test")

$body = @{
    required_status_checks = @{
        strict = $true
        contexts = $requiredChecks
    }
    enforce_admins = $false  # let the maintainer bypass for emergency hotfixes
    required_pull_request_reviews = @{
        required_approving_review_count = 0  # solo maintainer; raise to 1 when collaborators join
        dismiss_stale_reviews = $true
        require_code_owner_reviews = $false
    }
    restrictions = $null
    required_linear_history = $true
    allow_force_pushes = $false
    allow_deletions = $false
    required_conversation_resolution = $true
} | ConvertTo-Json -Depth 6

Write-Host "Applying branch protection to $Owner/$Repo@$Branch..." -ForegroundColor Cyan
$body | gh api `
    --method PUT `
    -H "Accept: application/vnd.github+json" `
    "/repos/$Owner/$Repo/branches/$Branch/protection" `
    --input -

Write-Host "Done. Verify in GitHub UI: https://github.com/$Owner/$Repo/settings/branches" -ForegroundColor Green
