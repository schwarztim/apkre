"""Infer JSON Schema from captured request/response bodies."""
from __future__ import annotations

from typing import Any

try:
    from genson import SchemaBuilder
    GENSON_AVAILABLE = True
except ImportError:
    GENSON_AVAILABLE = False


class SchemaInferrer:
    """Infer JSONSchema from one or more JSON samples using genson."""

    def infer(self, sample: Any) -> dict:
        """Infer schema from a single JSON sample."""
        if not GENSON_AVAILABLE:
            return _manual_infer(sample)

        builder = SchemaBuilder()
        builder.add_object(sample)
        return builder.to_schema()

    def infer_merged(self, samples: list[Any]) -> dict:
        """Infer schema from multiple samples (widens schema across all)."""
        if not samples:
            return {}

        if not GENSON_AVAILABLE:
            merged = {}
            for s in samples:
                _deep_merge(merged, _manual_infer(s))
            return merged

        builder = SchemaBuilder()
        for s in samples:
            builder.add_object(s)
        return builder.to_schema()


# ── Fallback manual inference ──────────────────────────────────────────────────

def _manual_infer(value: Any, depth: int = 0) -> dict:
    """Naive recursive JSON schema inference without genson."""
    if depth > 8:
        return {}

    if value is None:
        return {"type": "null"}
    if isinstance(value, bool):
        return {"type": "boolean"}
    if isinstance(value, int):
        return {"type": "integer"}
    if isinstance(value, float):
        return {"type": "number"}
    if isinstance(value, str):
        schema: dict = {"type": "string"}
        if len(value) > 2:
            # Guess format hints
            if _looks_like_datetime(value):
                schema["format"] = "date-time"
            elif value.startswith("eyJ"):
                schema["description"] = "JWT token"
        return schema
    if isinstance(value, list):
        if not value:
            return {"type": "array", "items": {}}
        item_schemas = [_manual_infer(item, depth + 1) for item in value[:5]]
        # Merge item schemas
        merged_items = item_schemas[0]
        for s in item_schemas[1:]:
            _deep_merge(merged_items, s)
        return {"type": "array", "items": merged_items}
    if isinstance(value, dict):
        props = {k: _manual_infer(v, depth + 1) for k, v in value.items()}
        return {
            "type": "object",
            "properties": props,
            "required": list(value.keys()),
        }
    return {}


def _looks_like_datetime(s: str) -> bool:
    import re
    return bool(re.match(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}', s))


def _deep_merge(base: dict, override: dict) -> None:
    """Merge override into base in-place (for schema widening)."""
    for k, v in override.items():
        if k not in base:
            base[k] = v
        elif isinstance(base[k], dict) and isinstance(v, dict):
            _deep_merge(base[k], v)
        elif k == "required" and isinstance(base[k], list) and isinstance(v, list):
            # Keep only fields required in ALL samples
            base[k] = [f for f in base[k] if f in v]
        elif k == "type":
            if base[k] != v:
                base[k] = [base[k], v] if isinstance(base[k], str) else base[k]
