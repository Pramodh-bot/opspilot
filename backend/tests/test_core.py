import logging
import time

import jwt
import pytest

from app import security
from app.circuit_breaker import BreakerState, CircuitBreaker, CircuitOpenError
from app.logging_config import JsonFormatter, configure_logging, request_id_var


def test_password_hash_roundtrip():
    h = security.hash_password("S3cret-pass-99")
    assert security.verify_password("S3cret-pass-99", h)
    assert not security.verify_password("wrong", h)
    assert not security.verify_password("x", "not-a-bcrypt-hash")


def test_jwt_roundtrip_and_tamper():
    token = security.create_access_token(7, "admin")
    assert security.decode_access_token(token)["sub"] == "7"
    with pytest.raises(jwt.PyJWTError):
        security.decode_access_token(token + "x")


def test_jwt_expired(monkeypatch):
    from app.config import get_settings

    s = get_settings()
    expired = jwt.encode({"sub": "1", "exp": int(time.time()) - 10}, s.jwt_secret, algorithm=s.jwt_algorithm)
    with pytest.raises(jwt.ExpiredSignatureError):
        security.decode_access_token(expired)


def test_jwt_alg_none_rejected():
    forged = jwt.encode({"sub": "1", "exp": int(time.time()) + 60}, key="", algorithm="none")
    with pytest.raises(jwt.PyJWTError):
        security.decode_access_token(forged)


def test_constant_time_equals():
    assert security.constant_time_equals("abc", "abc")
    assert not security.constant_time_equals("abc", "abd")
    assert not security.constant_time_equals(None, "abc")
    assert not security.constant_time_equals("abc", "")


def test_login_throttle_locks_and_expires():
    now = [0.0]
    t = security.LoginThrottle(clock=lambda: now[0])
    for _ in range(5):
        assert not t.is_locked("k")
        t.record_failure("k")
    assert t.is_locked("k")
    now[0] += 10_000
    assert not t.is_locked("k")
    t.record_failure("k")
    t.reset("k")
    assert not t.is_locked("k")


def test_circuit_breaker_lifecycle():
    now = [0.0]
    cb = CircuitBreaker(failure_threshold=2, recovery_seconds=10, clock=lambda: now[0])

    def boom():
        raise RuntimeError("x")

    assert cb.call(lambda: 1) == 1
    for _ in range(2):
        with pytest.raises(RuntimeError):
            cb.call(boom)
    assert cb.state is BreakerState.open and cb.gauge_value() == 2
    with pytest.raises(CircuitOpenError):
        cb.call(lambda: 1)
    now[0] += 11
    assert cb.state is BreakerState.half_open and cb.gauge_value() == 1
    with pytest.raises(RuntimeError):  # failed probe re-opens immediately
        cb.call(boom)
    assert cb.state is BreakerState.open
    now[0] += 11
    assert cb.call(lambda: "ok") == "ok"
    assert cb.state is BreakerState.closed and cb.gauge_value() == 0


def test_circuit_breaker_single_probe():
    now = [0.0]
    cb = CircuitBreaker(failure_threshold=1, recovery_seconds=1, clock=lambda: now[0])
    with pytest.raises(RuntimeError):
        cb.call(lambda: (_ for _ in ()).throw(RuntimeError()))
    now[0] += 2

    def probe():
        with pytest.raises(CircuitOpenError):  # a concurrent call while the probe is in flight is rejected
            cb.call(lambda: 1)
        return "probed"

    assert cb.call(probe) == "probed"


def test_json_logging(capsys):
    configure_logging("INFO")
    token = request_id_var.set("rid-1")
    try:
        logging.getLogger("t").info("hello", extra={"incident_id": 5})
        try:
            raise ValueError("bad")
        except ValueError:
            logging.getLogger("t").exception("failed")
    finally:
        request_id_var.reset(token)
    lines = [line for line in capsys.readouterr().out.splitlines() if line.startswith("{")]
    import json

    first, second = json.loads(lines[0]), json.loads(lines[1])
    assert first["msg"] == "hello" and first["request_id"] == "rid-1" and first["incident_id"] == 5
    assert "ValueError" in second["exc"]
    assert isinstance(JsonFormatter().format(logging.LogRecord("n", 20, "", 0, "m", (), None)), str)
