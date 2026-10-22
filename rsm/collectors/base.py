from __future__ import annotations


def observation(source: str, kind: str, keys: dict | None = None, attrs: dict | None = None,
                ref: str | None = None) -> dict:
    clean_keys = {k: [x for x in v if x] for k, v in (keys or {}).items()}
    return {"source": source, "kind": kind, "ref": ref,
            "keys": {k: v for k, v in clean_keys.items() if v},
            "attrs": {k: v for k, v in (attrs or {}).items() if v not in (None, "", [], {})}}
