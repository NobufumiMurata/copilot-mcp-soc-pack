"""OpenAPI 3.0.1 downgrade helpers.

Microsoft Security Copilot only accepts OpenAPI 3.0 / 3.0.1 plugin
specifications (as of 2026-02, see
https://learn.microsoft.com/en-us/copilot/security/custom-plugins). FastAPI
emits 3.1.0 by default. The two incompatibilities that actually show up in
this codebase are:

1. Optional fields encoded as ``anyOf: [<schema>, {type: "null"}]`` instead
   of the 3.0 ``nullable: true`` convention.
2. The top-level ``openapi`` version string itself.

This module provides a single ``downgrade_to_3_0_1`` function that mutates
the schema dict in place. It is intentionally conservative — it only
collapses the ``anyOf``/``oneOf`` null pattern and never touches fields it
does not recognise, so adding new Pydantic models does not require updates
here.
"""

from __future__ import annotations

from typing import Any


def _collapse_nullable(schema: dict[str, Any]) -> None:
    """Collapse 3.1-style ``anyOf: [..., {type: null}]`` into 3.0 nullable."""
    for combiner in ("anyOf", "oneOf"):
        options = schema.get(combiner)
        if not isinstance(options, list):
            continue
        null_entries = [o for o in options if isinstance(o, dict) and o.get("type") == "null"]
        other_entries = [
            o for o in options if not (isinstance(o, dict) and o.get("type") == "null")
        ]
        if not null_entries:
            continue
        if len(other_entries) == 1:
            # Merge the single remaining option into the parent and mark nullable.
            merged = other_entries[0]
            schema.pop(combiner, None)
            for key, value in merged.items():
                schema.setdefault(key, value)
            schema["nullable"] = True
        else:
            schema[combiner] = other_entries
            schema["nullable"] = True


def _downgrade_examples(schema: dict[str, Any]) -> None:
    """Convert 3.1-style ``examples: [v1, v2]`` (plural) into 3.0 ``example: v1``.

    Pydantic v2 + FastAPI 0.110+ emit ``Field(..., examples=[...])`` as the
    OpenAPI 3.1 ``examples`` array on schemas. OpenAPI 3.0.x does not allow
    ``examples`` inside a Schema Object (it is reserved for Parameter and
    Media Type Objects there) and strict importers — including Microsoft
    Security Copilot's Agent Builder API Tool importer — reject the spec
    with "Failed to import OpenAPI spec".

    We collapse the array down to ``example: <first value>`` which is valid
    everywhere. Any non-Schema usage of ``examples`` (Parameter / Media
    Type Object) is left untouched because it is valid in both versions.
    """
    examples = schema.get("examples")
    if isinstance(examples, list) and examples and "example" not in schema:
        schema["example"] = examples[0]
        schema.pop("examples", None)
    elif isinstance(examples, list) and not examples:
        # Drop empty arrays which are also illegal in 3.0.
        schema.pop("examples", None)


def _walk(node: Any) -> None:
    if isinstance(node, dict):
        _collapse_nullable(node)
        _downgrade_examples(node)
        for value in node.values():
            _walk(value)
    elif isinstance(node, list):
        for item in node:
            _walk(item)


def downgrade_to_3_0_1(schema: dict[str, Any]) -> dict[str, Any]:
    """Mutate ``schema`` (a FastAPI-produced OpenAPI dict) to 3.0.1 in place."""
    schema["openapi"] = "3.0.1"
    _walk(schema.get("components", {}))
    _walk(schema.get("paths", {}))
    return schema
