"""Local SQLite cache for OSV API responses.

Querying the OSV API on every scan hammers the service and slows CI down.
Repeated scans of the same manifests are the norm (every commit/PR), so we
cache responses keyed by (ecosystem, name, version) with a configurable TTL.

The cache also makes `--offline` scans possible for air-gapped CI runners.
"""

import hashlib
import json
import os
import sqlite3
import time
from pathlib import Path


def default_cache_dir() -> str:
    base = os.environ.get("MYTOOL_CACHE_DIR")
    if not base:
        base = Path.home() / ".cache" / "mytool"
    return str(base)


def _key(ecosystem: str, name: str, version: str) -> str:
    return hashlib.sha256(
        f"{ecosystem}\x1f{name}\x1f{version}".encode("utf-8")
    ).hexdigest()


class OSVCache:
    def __init__(self, cache_dir: str | None = None, ttl_hours: float = 24.0):
        self.cache_dir = cache_dir or default_cache_dir()
        self.ttl_seconds = ttl_hours * 3600
        os.makedirs(self.cache_dir, exist_ok=True)
        self.db_path = os.path.join(self.cache_dir, "osv_cache.db")
        self._conn = sqlite3.connect(self.db_path)
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS queries (
                key TEXT PRIMARY KEY,
                ecosystem TEXT, name TEXT, version TEXT,
                response TEXT, updated_at REAL
            )"""
        )
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS vulns (
                id TEXT PRIMARY KEY,
                response TEXT,
                updated_at REAL
            )"""
        )
        self._conn.commit()

    def get(self, ecosystem: str, name: str, version: str):
        """Return cached vulns list or None if absent/stale."""
        k = _key(ecosystem, name, version)
        row = self._conn.execute(
            "SELECT response, updated_at FROM queries WHERE key=?", (k,)
        ).fetchone()
        if not row:
            return None
        response, updated_at = row
        if time.time() - updated_at > self.ttl_seconds:
            return None
        try:
            return json.loads(response)
        except ValueError:
            return None

    def put(self, ecosystem: str, name: str, version: str, vulns: list) -> None:
        k = _key(ecosystem, name, version)
        data = json.dumps(vulns)
        self._conn.execute(
            """INSERT INTO queries(key, ecosystem, name, version, response, updated_at)
               VALUES(?,?,?,?,?,?)
               ON CONFLICT(key) DO UPDATE SET
                 response=excluded.response, updated_at=excluded.updated_at""",
            (k, ecosystem, name, version, data, time.time()),
        )
        self._conn.commit()

    # -- individual vuln records (full advisory bodies) ---------------------
    def get_vuln(self, vuln_id: str):
        """Return a cached full vuln record or None."""
        row = self._conn.execute(
            "SELECT response, updated_at FROM vulns WHERE id=?", (vuln_id,)
        ).fetchone()
        if not row:
            return None
        response, updated_at = row
        if time.time() - updated_at > self.ttl_seconds:
            return None
        try:
            return json.loads(response)
        except ValueError:
            return None

    def put_vuln(self, vuln_id: str, vuln: dict) -> None:
        self._conn.execute(
            """INSERT INTO vulns(id, response, updated_at) VALUES(?,?,?)
               ON CONFLICT(id) DO UPDATE SET
                 response=excluded.response, updated_at=excluded.updated_at""",
            (vuln_id, json.dumps(vuln), time.time()),
        )
        self._conn.commit()

    def size(self) -> int:
        return self._conn.execute("SELECT COUNT(*) FROM queries").fetchone()[0]

    def clear(self) -> None:
        self._conn.execute("DELETE FROM queries")
        self._conn.execute("DELETE FROM vulns")
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()


# Negated-cache markers: OSV returns "no vulns" for most queries; caching
# empty results is just as valuable as caching real hits.
_NO_RESULT = -1


def has_vulns(vulns) -> bool:
    return bool(vulns)