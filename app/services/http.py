"""Shared HTTP helpers with retry, timeout, and on-disk caching."""
from __future__ import annotations

import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Any

import httpx

from app.core.config import settings

logger = logging.getLogger("veylix.http")

_cache_dir = Path(settings.data_dir) / "cache"
_cache_dir.mkdir(parents=True, exist_ok=True)

USER_AGENT = "Veylix/0.1 (Security Intelligence Platform)"


def cache_key(url: str, params: dict | None = None) -> Path:
    raw = json.dumps({"url": url, "params": params or {}}, sort_keys=True)
    digest = hashlib.sha256(raw.encode()).hexdigest()[:32]
    return _cache_dir / f"{digest}.json"


def read_cache(key: Path, max_age_seconds: int | None) -> dict | list | None:
    if not key.exists():
        return None
    if max_age_seconds is not None:
        age = time.time() - key.stat().st_mtime
        if age > max_age_seconds:
            return None
    try:
        return json.loads(key.read_text(encoding="utf-8"))
    except Exception:
        logger.warning("Corrupt cache file %s ignored", key)
        return None


def write_cache(key: Path, payload: Any) -> None:
    try:
        key.write_text(json.dumps(payload), encoding="utf-8")
    except Exception as exc:
        logger.warning("Could not write cache %s: %s", key, exc)


def fetch_json(
    url: str,
    params: dict | None = None,
    headers: dict | None = None,
    *,
    cache_ttl: int | None = 3600,
    timeout: int | None = None,
    max_retries: int | None = None,
    respect_rate_limit: bool = True,
) -> Any:
    """GET a JSON URL with on-disk caching, retries with backoff, human UA.

    cache_ttl: seconds a cached copy is considered fresh (None disables caching)
    """
    timeout = timeout if timeout is not None else settings.veylix_request_timeout
    max_retries = max_retries if max_retries is not None else settings.veylix_max_retries

    key = cache_key(url, params)
    if cache_ttl is not None:
        cached = read_cache(key, cache_ttl)
        if cached is not None:
            return cached

    h = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if headers:
        h.update(headers)

    last_exc: Exception | None = None
    backoff = 2.0
    for attempt in range(max_retries + 1):
        try:
            resp = httpx.get(url, params=params, headers=h, timeout=timeout, follow_redirects=True, verify=True)
            if resp.status_code in (429, 503) and attempt < max_retries and respect_rate_limit:
                retry_after = resp.headers.get("Retry-After")
                wait = float(retry_after) if retry_after else backoff
                logger.info("Rate-limited (%s); waiting %.1fs", resp.status_code, wait)
                time.sleep(wait)
                backoff *= 2
                continue
            resp.raise_for_status()
            data = resp.json()
            write_cache(key, data)
            return data
        except (httpx.HTTPError, ValueError) as exc:
            last_exc = exc
            logger.warning("Attempt %d/%d failed for %s: %s", attempt + 1, max_retries + 1, url, exc)
            if attempt < max_retries:
                time.sleep(backoff)
                backoff *= 2
    raise ConnectionError(f"Could not fetch {url} after {max_retries + 1} attempts: {last_exc}")
