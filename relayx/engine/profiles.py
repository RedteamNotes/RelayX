from __future__ import annotations

import json
from pathlib import Path
from typing import Any


PROFILE_DIR = Path(__file__).resolve().parents[1] / "profiles"


def load_profile(value: str | None) -> dict[str, Any]:
    if not value:
        return {}
    path = _profile_path(value)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"profile {path} is not valid JSON: {exc.msg}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"profile {path} must contain a JSON object")
    return data


def list_profiles() -> list[dict[str, str]]:
    if not PROFILE_DIR.exists():
        return []
    rows = []
    for path in sorted(PROFILE_DIR.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            data = {}
        rows.append(
            {
                "name": path.stem,
                "path": str(path),
                "description": str(data.get("description", "")) if isinstance(data, dict) else "",
            }
        )
    return rows


def render_profiles(rows: list[dict[str, str]]) -> str:
    if not rows:
        return "No RelayX profiles found."
    lines = ["RelayX Profiles", ""]
    for row in rows:
        lines.append(f"- {row['name']}")
        if row["description"]:
            lines.append(f"  {row['description']}")
        lines.append(f"  path: {row['path']}")
    return "\n".join(lines)


def profiles_to_json(rows: list[dict[str, str]]) -> str:
    return json.dumps({"profiles": rows}, indent=2, sort_keys=True)


def profile_value(profile: dict[str, Any], key: str, default: Any = None) -> Any:
    return profile.get(key, default)


def profile_bool(profile: dict[str, Any], key: str, default: bool = False) -> bool:
    value = profile.get(key, default)
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on", "enabled"}


def _profile_path(value: str) -> Path:
    path = Path(value)
    if path.exists():
        return path
    candidate = PROFILE_DIR / f"{value}.json"
    if candidate.exists():
        return candidate
    raise ValueError(f"profile does not exist: {value}")
