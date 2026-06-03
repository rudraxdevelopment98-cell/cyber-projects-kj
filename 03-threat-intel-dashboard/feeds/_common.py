"""Shared helpers for feed collectors."""

import sys


def http_get(url, headers=None, params=None, timeout=20):
    """GET wrapper that imports requests lazily and degrades gracefully.

    Returns the ``requests.Response`` on success or ``None`` on any failure, so
    feed modules can simply ``if resp is None: return []``.
    """
    try:
        import requests
    except ImportError:
        print("[feeds] 'requests' not installed; skipping live fetch.", file=sys.stderr)
        return None
    try:
        resp = requests.get(url, headers=headers or {}, params=params or {}, timeout=timeout)
        resp.raise_for_status()
        return resp
    except Exception as exc:  # noqa: BLE001 - feeds must never hard-fail the run
        print(f"[feeds] GET {url} failed: {exc}", file=sys.stderr)
        return None


def http_post(url, json=None, data=None, headers=None, timeout=20):
    """POST wrapper mirroring :func:`http_get`."""
    try:
        import requests
    except ImportError:
        print("[feeds] 'requests' not installed; skipping live fetch.", file=sys.stderr)
        return None
    try:
        resp = requests.post(url, json=json, data=data, headers=headers or {}, timeout=timeout)
        resp.raise_for_status()
        return resp
    except Exception as exc:  # noqa: BLE001
        print(f"[feeds] POST {url} failed: {exc}", file=sys.stderr)
        return None


def make_ioc(value, ioc_type, source, first_seen="", tags=None):
    """Build a normalised IOC dict."""
    return {
        "ioc": value,
        "type": ioc_type,
        "source": source,
        "first_seen": first_seen or "",
        "tags": tags or [],
    }
