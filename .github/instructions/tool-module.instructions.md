---
applyTo: "src/tools/**/*.py"
---

# Tool Module Instructions

`src/tools/` 配下のモジュールは **1 ファイル = 1 外部 API カテゴリ** として実装する。

## 必須構造

```python
"""<Service Name> tool.

<Service description, links to docs, auth requirements.>
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from fastmcp import FastMCP
from pydantic import BaseModel

from src.common.http import TTLCache, get_client

# --- Constants --------------------------------------------------------------
SERVICE_URL = "https://api.example.com/"
SERVICE_AUTH_KEY_ENV = "SERVICE_AUTH_KEY"  # if auth is required

router = APIRouter(prefix="/service", tags=["service"])
_cache = TTLCache(ttl_seconds=...)  # Choose TTL appropriate for the API's rate limit.


# --- Models -----------------------------------------------------------------
class MyResult(BaseModel):
    ...


# --- Pure async helpers (the source of truth) ------------------------------
async def _do_thing(arg: str) -> list[MyResult]:
    ...


# --- REST endpoints (OpenAPI → Security Copilot) ---------------------------
@router.get(
    "/action",
    response_model=list[MyResult],
    summary="Short imperative summary",
    description="Longer description used by Security Copilot for planning.",
)
async def action_endpoint(arg: str = Query(..., examples=["..."])) -> list[MyResult]:
    return await _do_thing(arg)


# --- MCP tools --------------------------------------------------------------
def register_mcp_tools(mcp: FastMCP) -> None:
    @mcp.tool(
        name="service_action",
        description="Description used by MCP-side LLMs. Be explicit about inputs/outputs.",
    )
    async def action_mcp(arg: str) -> list[dict[str, Any]]:
        return [r.model_dump() for r in await _do_thing(arg)]
```

## チェックリスト

- [ ] pure helper 関数を実装しているか (router と mcp ツールが helper を呼ぶ)
- [ ] `_cache` で TTL キャッシュを使用しているか
- [ ] 認証必須の API では、環境変数未設定時に 503 で明示的なエラーメッセージを返すか
- [ ] `summary` と `description` を両方に書いているか
- [ ] Pydantic モデルで入出力を型付けしているか
- [ ] 行長 100 以下、ruff パス
- [ ] `src/app.py` に `from src.tools import <new>` と 2 行追加したか
- [ ] `tests/test_app.py` の `test_openapi_schema_contains_tools` に新エンドポイントを追加したか

## やってはいけないこと

- 複数の外部 API を 1 ファイルに混ぜる (abuse.ch のように **同一サービスの複数エンドポイント** は OK、別プロバイダは別ファイル)
- router と mcp ツールで **ロジックを重複実装** する (pure helper を必ず経由)
- API キーを URL やエラーメッセージに混入させる
- 同期 HTTP クライアント (`requests` 等) を使う
