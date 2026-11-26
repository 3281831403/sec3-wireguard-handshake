import json

from wghand.check import (
    _mac,
    check_mac,
    check_timestamp,
    check_type,
    handshake_batch,
    parse_message,
)

PEER = "peer-alpha"
KEY = "handshake-key"


def _message(**overrides):
    msg = {
        "type": "init",
        "session_id": "session-1",
        "timestamp": 900,
        "peer": PEER,
    }
    msg.update(overrides)
    msg["mac"] = _mac(msg, KEY)
    return msg


def test_parse_message_requires_complete_handshake():
    raw = json.dumps(
        {
            "type": "init",
            "session_id": "session-1",
            "timestamp": 900,
            "peer": PEER,
        }
    ).encode("utf-8")

    accepted = True
    try:
        parse_message(raw)
    except ValueError:
        accepted = False

    assert accepted is False


def test_check_type_rejects_wrong_phase():
    msg = _message()

    assert check_type(msg, "init") is True
    assert check_type(msg, "response") is False


def test_timestamp_rejects_replay_of_last_value():
    state = {"last_timestamp": 100, "window": 60, "window_start": 40}

    assert check_timestamp({"timestamp": 100}, state, 100) is False


def test_check_mac_rejects_tampered_payload():
    msg = _message()
    tampered = dict(msg)
    tampered["session_id"] = "session-2"

    assert check_mac(tampered, KEY) is False


def test_handshake_batch_keeps_messages_independent():
    state = {
        "last_timestamp": 700,
        "window": 300,
        "window_start": 400,
        "now": 1000,
        "session_id": "session-0",
        "key": KEY,
    }
    messages = [_message(timestamp=900), _message(timestamp=800)]

    result = handshake_batch(messages, state, {PEER})

    assert result["accepted"] == [0, 1]