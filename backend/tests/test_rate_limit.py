"""Upload rate limiting (in-memory, per client IP)."""
import time

import app.routers.upload as upload_mod
from app.services.ratelimit import InMemoryRateLimiter


# --- unit: InMemoryRateLimiter --------------------------------------------

def test_limiter_allows_then_rejects():
    limiter = InMemoryRateLimiter(limit=3, window_seconds=60)
    assert [limiter.allow("ip-1") for _ in range(3)] == [(True, 0), (True, 0), (True, 0)]
    allowed, retry_after = limiter.allow("ip-1")
    assert allowed is False
    assert retry_after > 0


def test_limiter_tracks_keys_independently():
    limiter = InMemoryRateLimiter(limit=1, window_seconds=60)
    assert limiter.allow("a") == (True, 0)
    assert limiter.allow("a") == (False, 60)
    assert limiter.allow("b") == (True, 0)


def test_limiter_window_rolls_over():
    limiter = InMemoryRateLimiter(limit=1, window_seconds=0.2)
    assert limiter.allow("ip") == (True, 0)
    time.sleep(0.25)
    assert limiter.allow("ip") == (True, 0)


def test_limiter_rejects_invalid_config():
    try:
        InMemoryRateLimiter(limit=0, window_seconds=60)
    except ValueError:
        pass
    else:
        raise AssertionError("limit=0 must raise ValueError")


# --- integration: POST /api/samples/upload returns 429 --------------------

def _upload(client, name, content):
    return client.post(
        "/api/samples/upload",
        files={"file": (name, content, "application/octet-stream")},
    )


def test_upload_endpoint_enforces_rate_limit(client):
    original = upload_mod._upload_limiter
    upload_mod._upload_limiter = InMemoryRateLimiter(limit=2, window_seconds=60)
    try:
        ok1 = _upload(client, "r1.bin", b"MZ-r1-" + b"\x00" * 40)
        ok2 = _upload(client, "r2.bin", b"MZ-r2-" + b"\x00" * 40)
        assert ok1.status_code == 201
        assert ok2.status_code == 201

        blocked = _upload(client, "r3.bin", b"MZ-r3-" + b"\x00" * 40)
        assert blocked.status_code == 429
        body = blocked.json()
        assert "too many upload requests" in body["detail"].lower()
        assert "request_id" in body
        assert body["request_id"] == blocked.headers["X-Request-ID"]
        assert int(blocked.headers["Retry-After"]) > 0
    finally:
        upload_mod._upload_limiter = original


def test_rate_limit_recovers_after_window(client):
    original = upload_mod._upload_limiter
    upload_mod._upload_limiter = InMemoryRateLimiter(limit=1, window_seconds=0.2)
    try:
        first = _upload(client, "win1.bin", b"MZ-win1-" + b"\x00" * 40)
        assert first.status_code == 201
        blocked = _upload(client, "win2.bin", b"MZ-win2-" + b"\x00" * 40)
        assert blocked.status_code == 429
        time.sleep(0.25)
        retry = _upload(client, "win3.bin", b"MZ-win3-" + b"\x00" * 40)
        assert retry.status_code == 201
    finally:
        upload_mod._upload_limiter = original