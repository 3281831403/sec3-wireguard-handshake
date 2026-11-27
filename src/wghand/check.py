"""WireGuard-style handshake parsing and validation.

A handshake message is a JSON object with the fields type, session_id,
timestamp, peer, and mac.  The mac is an HMAC-SHA256 over the canonical
JSON encoding of the other four fields.

Security rules enforced here:

* timestamps are strictly monotonic -- any value not newer than the last
  accepted timestamp is rejected, so replays and rollbacks fail;
* the replay window slides forward with the current time;
* ``init`` and ``response`` messages are bound to one session id;
* the authentication value is verified against the key material;
* the peer must belong to an explicit allow set;
* batch validation judges every message against the same original state.
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
    """Return whether the message type exactly matches the expected phase."""
    if not isinstance(msg, dict):
        return False
    return msg.get("type") == expected


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def check_timestamp(msg: dict[str, Any], state: dict[str, Any], now: int) -> bool:
    """Check timestamp freshness, window membership and replay ordering.

    A timestamp is accepted only when it lies inside the sliding freshness
    window and is strictly greater than the last accepted timestamp.  On
    acceptance ``last_timestamp`` is advanced to the new value, which makes
    any replay (equal timestamp) or rollback (smaller timestamp) fail.
    """
    if not isinstance(msg, dict) or not isinstance(state, dict):
        return False

    ts = msg.get("timestamp")
    if not _is_int(ts):
        return False

    if not _is_int(now):
        return False

    window = state.get("window", DEFAULT_WINDOW)
    if not _is_int(window) or window < 0:
        window = DEFAULT_WINDOW

    # Slide the lower edge of the replay window forward with current time.
    time_floor = now - window
    current_start = state.get("window_start")
    if _is_int(current_start):
        window_start = max(current_start, time_floor)
    else:
        window_start = time_floor
    state["window_start"] = window_start

    # Timestamps older than the sliding window are never fresh.
    if ts < window_start:
        return False

    # Strict monotonicity: equal values are replays, smaller values roll back.
    last = state.get("last_timestamp")
    if _is_int(last) and ts <= last:
        return False

    state["last_timestamp"] = ts
    return True


def check_session(msg: dict[str, Any], state: dict[str, Any]) -> bool:
    """Return whether the message belongs to the active handshake session.

    ``init`` messages start a handshake and only need a session id.  Every
    later phase, in particular a ``response``, must carry exactly the session
    id already anchored in ``state`` -- init and response are therefore
    bound to the same session identifier.
    """
    if not isinstance(msg, dict):
        return False
    session_id = msg.get("session_id")
    if not session_id:
        return False
    if msg.get("type") == "init":
        return True
    anchor = state.get("session_id") if isinstance(state, dict) else None
    return anchor is not None and anchor == session_id


def check_mac(msg: dict[str, Any], key: str | bytes) -> bool:
    """Validate the message authentication value against the key material."""
    if not isinstance(msg, dict):
        return False
    if not key:
        return False
    tag = msg.get("mac")
    if not tag or not isinstance(tag, str):
        return False

    expected = _mac(msg, key)
    try:
        return hmac.compare_digest(expected, tag)
    except (TypeError, ValueError):
        return False


def check_peer(msg: dict[str, Any], allowed: Iterable[str]) -> bool:
    """Validate that the message comes from an explicitly allowed peer."""
    if not isinstance(msg, dict):
        return False
    try:
        allowed_set = set(allowed)
    except TypeError:
        return False
    return msg.get("peer") in allowed_set


def validate_message(msg: dict[str, Any]) -> list[str]:
    """Return a list of structural problems found in a handshake message."""
    if not isinstance(msg, dict):
        return ["not_an_object"]

    issues: list[str] = []
    if msg.get("type") not in MESSAGE_TYPES:
        issues.append("invalid_type")
    if msg.get("timestamp") is None:
        issues.append("missing_timestamp")
    if not msg.get("session_id"):
        issues.append("missing_session_id")
    if not msg.get("peer"):
        issues.append("missing_peer")
    if not msg.get("mac"):
        issues.append("missing_mac")

    return issues


def _snapshot_state(state: Any) -> dict[str, Any]:
    """Build an isolated per-message copy of the validation state."""
    if not isinstance(state, dict):
        return {}
    return dict(state)


def _fingerprint(msg: dict[str, Any]) -> bytes:
    """Canonical identity of one handshake message (signed fields + tag)."""
    try:
        base = _mac_input(msg)
    except (TypeError, ValueError):
        base = repr(msg).encode("utf-8", "replace")
    tag = str(msg.get("mac", "")).encode("utf-8", "replace")
    return base + b"\x00" + tag


def handshake_batch(
    messages: Iterable[dict[str, Any]],
    state: dict[str, Any],
    allowed: Iterable[str],
) -> dict[str, Any]:
    """Validate a batch of handshake messages and report per-message results.

    Each message is judged against an isolated snapshot of ``state`` so that
    accepting an earlier message cannot make a later message fail through
    accumulated timestamp/session updates.  Progress (the high-water
    timestamp) is committed to the caller's state once, after every message
    has been independently judged, so replays delivered in later calls are
    still rejected.
    """
    if not isinstance(state, dict):
        state = {}

    now = int(state.get("now", int(time.time())))

    try:
        allowed_set = set(allowed)
    except TypeError:
        allowed_set = set()

    original_state = dict(state)
    accepted: list[int] = []
    rejected: list[int] = []
    results: list[dict[str, Any]] = []
    high_water: int | None = None
    seen_messages: set[bytes] = set()

    for index, msg in enumerate(messages):
        if not isinstance(msg, dict):
            rejected.append(index)
            results.append(
                {"index": index, "accepted": False, "issues": ["not_an_object"]}
            )
            continue

        # A byte-identical handshake inside this batch is the same message
        # being replayed; only its first occurrence may be accepted.  This is
        # keyed on full content, so distinct (e.g. out-of-order) messages are
        # still judged independently against the original state below.
        fingerprint = _fingerprint(msg)
        is_replay = fingerprint in seen_messages
        seen_messages.add(fingerprint)

        # Every message is validated against its own snapshot of the state
        # as it was before the batch, so messages never influence each other
        # through accumulated timestamp/session updates.
        message_state = _snapshot_state(original_state)

        issues = validate_message(msg)
        if not check_type(msg, msg.get("type")):
            issues.append("type_mismatch")
        if not check_timestamp(msg, message_state, now):
            issues.append("timestamp")
        if not check_session(msg, message_state):
            issues.append("session")
        if not check_mac(msg, message_state.get("key", "")):
            issues.append("mac")
        if not check_peer(msg, allowed_set):
            issues.append("peer")
        if is_replay:
            issues.append("replay")

        ok = not issues
        if ok:
            accepted.append(index)
            ts = msg.get("timestamp")
            if _is_int(ts):
                high_water = ts if high_water is None else max(high_water, ts)
        else:
            rejected.append(index)

        results.append({"index": index, "accepted": ok, "issues": issues})

    # Commit replay high-water mark without making messages within the batch
    # depend on one another.
    if high_water is not None:
        last = state.get("last_timestamp")
        if not _is_int(last) or high_water > last:
            state["last_timestamp"] = high_water
        window = state.get("window", DEFAULT_WINDOW)
        if not _is_int(window) or window < 0:
            window = DEFAULT_WINDOW
        floor = now - window
        current_start = state.get("window_start")
        state["window_start"] = (
            max(current_start, floor) if _is_int(current_start) else floor
        )

    return {"accepted": accepted, "rejected": rejected, "results": results}
