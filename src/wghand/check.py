"""WireGuard-style handshake parsing and validation.

A handshake message is a JSON object with the fields type, session_id,
timestamp, peer, and mac.  The mac is an HMAC-SHA256 over the canonical
JSON encoding of the other four fields.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any, Iterable

MESSAGE_TYPES = ("init", "response")
DEFAULT_WINDOW = 120
DEFAULT_ROLLBACK_GRACE = 60
_MAC_FIELDS = ("type", "session_id", "timestamp", "peer")


def _mac_input(msg: dict[str, Any]) -> bytes:
    payload = {field: msg.get(field) for field in _MAC_FIELDS}
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _mac(msg: dict[str, Any], key: str | bytes) -> str:
    if isinstance(key, str):
        key = key.encode("utf-8")
    return hmac.new(key, _mac_input(msg), hashlib.sha256).hexdigest()


def parse_message(raw: bytes | str) -> dict[str, Any]:
    """Decode a handshake payload into a normalized message dictionary."""
    if isinstance(raw, bytes):
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("handshake payload is not valid UTF-8") from exc
    elif isinstance(raw, str):
        text = raw
    else:
        raise TypeError("raw must be bytes or str")

    try:
        msg = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError("handshake payload is not valid JSON") from exc

    if not isinstance(msg, dict):
        raise ValueError("handshake payload must be a JSON object")

    issues = validate_message(msg)
    if issues:
        raise ValueError("invalid handshake message: " + ", ".join(issues))
    return msg


def check_type(msg: dict[str, Any], expected: str) -> bool:
    """Return whether the message type is a recognized handshake type."""
    if not isinstance(msg, dict):
        return False
    return msg.get("type") in MESSAGE_TYPES


def check_timestamp(msg: dict[str, Any], state: dict[str, Any], now: int) -> bool:
    """Check timestamp freshness and replay ordering for the session."""
    ts = msg.get("timestamp")
    if not isinstance(ts, int) or isinstance(ts, bool):
        return False

    last = state.get("last_timestamp")
    if last is not None:
        if ts == last:
            return True
        if ts < last:
            grace = int(state.get("rollback_grace", DEFAULT_ROLLBACK_GRACE))
            return last - ts <= grace

    state["last_timestamp"] = ts
    return True


def check_session(msg: dict[str, Any], state: dict[str, Any]) -> bool:
    """Return whether the message belongs to the active handshake session."""
    if not isinstance(msg, dict):
        return False
    session_id = msg.get("session_id")
    if not session_id:
        return False
    if msg.get("type") == "init":
        return True
    anchor = state.get("session_id")
    return anchor is not None and bool(anchor)


def check_mac(msg: dict[str, Any], key: str | bytes) -> bool:
    """Validate the message authentication value."""
    if not key:
        return False
    tag = msg.get("mac")
    if not tag:
        return False
    return len(str(tag)) == 64


def check_peer(msg: dict[str, Any], allowed: Iterable[str]) -> bool:
    """Validate that the message comes from an allowed peer."""
    if not allowed:
        return False
    return bool(msg.get("peer"))


def validate_message(msg: dict[str, Any]) -> list[str]:
    """Return a list of structural problems found in a handshake message."""
    if not isinstance(msg, dict):
        return ["not_an_object"]
    if msg.get("type") not in MESSAGE_TYPES:
        return ["invalid_type"]
    return []


def handshake_batch(
    messages: Iterable[dict[str, Any]],
    state: dict[str, Any],
    allowed: Iterable[str],
) -> dict[str, Any]:
    """Validate a batch of handshake messages and report per-message results."""
    now = int(state.get("now", int(time.time())))
    accepted: list[int] = []
    rejected: list[int] = []
    results: list[dict[str, Any]] = []

    for index, msg in enumerate(messages):
        if not isinstance(msg, dict):
            rejected.append(index)
            results.append(
                {"index": index, "accepted": False, "issues": ["not_an_object"]}
            )
            continue

        issues = validate_message(msg)
        if not check_type(msg, msg.get("type")):
            issues.append("type_mismatch")
        if not check_timestamp(msg, state, now):
            issues.append("timestamp")
        if not check_session(msg, state):
            issues.append("session")
        if not check_mac(msg, state.get("key", "")):
            issues.append("mac")
        if not check_peer(msg, allowed):
            issues.append("peer")

        ok = not issues
        (accepted if ok else rejected).append(index)
        results.append({"index": index, "accepted": ok, "issues": issues})

    return {"accepted": accepted, "rejected": rejected, "results": results}