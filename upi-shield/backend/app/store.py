"""Persistent candidate store backed by SQLite (stdlib ``sqlite3``).

The public surface is intentionally unchanged from the original in-memory store:
``store.candidates`` (dict by id), ``store.campaigns`` (list), ``add()`` and
``recluster()``. Candidates are kept in memory for fast reads and written through to
SQLite, so data survives restarts. Use ``":memory:"`` as the path for an ephemeral
store (the test suite does).

Ingesting a URL that is already known (after normalisation) updates the existing
candidate instead of creating a duplicate: the original id and ``first_seen`` are
kept, ``last_seen`` and ``sightings`` advance, the latest analysis replaces the
score/signals, and infrastructure entities are merged.
"""
from __future__ import annotations

import logging
import os
import sqlite3
import threading
from collections.abc import Iterable
from datetime import UTC, datetime
from urllib.parse import urlsplit, urlunsplit

from app.config import get_settings
from app.schemas import Campaign, Candidate, Job
from app.services.clustering import build_campaigns

logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS candidates (
    id          TEXT PRIMARY KEY,
    url_key     TEXT NOT NULL UNIQUE,
    domain      TEXT NOT NULL,
    risk_score  REAL NOT NULL,
    verdict     TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    payload     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_candidates_domain ON candidates(domain);
CREATE INDEX IF NOT EXISTS idx_candidates_score ON candidates(risk_score);
CREATE TABLE IF NOT EXISTS jobs (
    id          TEXT PRIMARY KEY,
    created_at  TEXT NOT NULL,
    payload     TEXT NOT NULL
);
"""

_DEFAULT_PORTS = {"http": 80, "https": 443}


def normalize_url(url: str) -> str:
    """Canonical form used for de-duplication.

    Lower-cases the scheme and host, adds ``http://`` when missing, drops default
    ports, fragments and a bare trailing slash. Path and query are preserved because
    phishing kits frequently differentiate victims by path.
    """
    raw = (url or "").strip()
    if "://" not in raw:
        raw = "http://" + raw
    parts = urlsplit(raw)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower().rstrip(".")
    netloc = host
    if parts.port and _DEFAULT_PORTS.get(scheme) != parts.port:
        netloc = f"{host}:{parts.port}"
    path = parts.path or ""
    if path == "/":
        path = ""
    return urlunsplit((scheme, netloc, path, parts.query, ""))


class Store:
    def __init__(self, path: str | None = None) -> None:
        self.path = path or get_settings().database_path
        self.candidates: dict[str, Candidate] = {}
        self.campaigns: list[Campaign] = []
        self._url_index: dict[str, str] = {}  # normalised URL -> candidate id
        self._lock = threading.RLock()
        self._conn = self._connect(self.path)
        self.load()

    # -- connection -------------------------------------------------------------
    @staticmethod
    def _connect(path: str) -> sqlite3.Connection:
        if path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        conn = sqlite3.connect(path, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL" if path != ":memory:" else "PRAGMA journal_mode=MEMORY")
        conn.executescript(_SCHEMA)
        return conn

    def load(self) -> None:
        """(Re)load all candidates from SQLite and rebuild campaigns."""
        with self._lock:
            rows = self._conn.execute("SELECT payload FROM candidates").fetchall()
            self.candidates = {}
            for (payload,) in rows:
                try:
                    cand = Candidate.model_validate_json(payload)
                    self.candidates[cand.id] = cand
                except Exception as exc:  # noqa: BLE001 - skip a corrupt row, keep serving
                    logger.warning("store: skipping unreadable candidate row: %s", exc)
            self._recluster_locked(persist=False)

    # -- candidates -------------------------------------------------------------
    def find_by_url(self, url: str) -> Candidate | None:
        with self._lock:
            cid = self._url_index.get(normalize_url(url))
            cand = self.candidates.get(cid) if cid else None
            if cand is None and len(self._url_index) != len(self.candidates):
                # The dict was modified directly (e.g. by tests or seeding); resync once.
                self._rebuild_index_locked()
                cid = self._url_index.get(normalize_url(url))
                cand = self.candidates.get(cid) if cid else None
            return cand

    def _rebuild_index_locked(self) -> None:
        self._url_index = {normalize_url(c.url): c.id for c in self.candidates.values()}

    def _merge(self, existing: Candidate, incoming: Candidate) -> Candidate:
        seen = {(e.type, e.value) for e in incoming.entities}
        merged_entities = list(incoming.entities)
        for e in existing.entities:
            if (e.type, e.value) not in seen:
                seen.add((e.type, e.value))
                merged_entities.append(e)
        return incoming.model_copy(update={
            "id": existing.id,
            "first_seen": min(existing.first_seen, incoming.first_seen),
            "last_seen": max(existing.last_seen or existing.first_seen, incoming.first_seen),
            "sightings": existing.sightings + 1,
            "entities": merged_entities,
            "screenshot_url": incoming.screenshot_url or existing.screenshot_url,
            "visual_similarity": (incoming.visual_similarity
                                  if incoming.visual_similarity is not None else existing.visual_similarity),
        })

    def _upsert_locked(self, cand: Candidate) -> Candidate:
        existing = self.find_by_url(cand.url)
        stored = self._merge(existing, cand) if existing and existing.id != cand.id else cand
        self.candidates[stored.id] = stored
        self._url_index[normalize_url(stored.url)] = stored.id
        return stored

    def add(self, cand: Candidate) -> Candidate:
        """Insert or update one candidate, then recluster. Returns the stored record."""
        with self._lock:
            stored = self._upsert_locked(cand)
            self._recluster_locked()
            return self.candidates[stored.id]

    def add_many(self, cands: Iterable[Candidate]) -> list[Candidate]:
        """Insert or update many candidates with a single recluster pass."""
        with self._lock:
            ids = [self._upsert_locked(c).id for c in cands]
            self._recluster_locked()
            return [self.candidates[i] for i in ids]

    def update(self, cand: Candidate) -> Candidate:
        """Replace a candidate by id (no URL merge), then recluster."""
        with self._lock:
            self.candidates[cand.id] = cand
            self._recluster_locked()
            return self.candidates[cand.id]

    def clear(self) -> None:
        with self._lock:
            self.candidates.clear()
            self._url_index.clear()
            self.campaigns = []
            self._conn.execute("DELETE FROM candidates")
            self._conn.commit()

    # -- clustering ---------------------------------------------------------------
    def recluster(self) -> None:
        with self._lock:
            self._recluster_locked()

    def _recluster_locked(self, persist: bool = True) -> None:
        self._rebuild_index_locked()
        for c in self.candidates.values():
            c.campaign_id = None
        self.campaigns = build_campaigns(list(self.candidates.values()))
        for camp in self.campaigns:
            for cid in camp.candidate_ids:
                self.candidates[cid].campaign_id = camp.id
        if persist:
            self._persist_all_locked()

    def _persist_all_locked(self) -> None:
        rows = [(c.id, normalize_url(c.url), c.domain, c.risk_score, c.verdict,
                 c.first_seen.isoformat(), c.model_dump_json()) for c in self.candidates.values()]
        with self._conn:
            ids = [r[0] for r in rows]
            if ids:
                marks = ",".join("?" * len(ids))
                self._conn.execute(f"DELETE FROM candidates WHERE id NOT IN ({marks})", ids)
            else:
                self._conn.execute("DELETE FROM candidates")
            self._conn.executemany(
                "INSERT INTO candidates (id, url_key, domain, risk_score, verdict, first_seen, payload) "
                "VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET url_key=excluded.url_key, domain=excluded.domain, "
                "risk_score=excluded.risk_score, verdict=excluded.verdict, "
                "first_seen=excluded.first_seen, payload=excluded.payload",
                rows,
            )

    # -- jobs ---------------------------------------------------------------------
    def save_job(self, job: Job) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO jobs (id, created_at, payload) VALUES (?, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET payload=excluded.payload",
                (job.id, job.created_at.isoformat(), job.model_dump_json()),
            )

    def get_job(self, job_id: str) -> Job | None:
        with self._lock:
            row = self._conn.execute("SELECT payload FROM jobs WHERE id = ?", (job_id,)).fetchone()
        return Job.model_validate_json(row[0]) if row else None

    def list_jobs(self, limit: int = 50) -> list[Job]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT payload FROM jobs ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [Job.model_validate_json(r[0]) for r in rows]

    def stats(self) -> dict:
        with self._lock:
            verdicts: dict[str, int] = {}
            for c in self.candidates.values():
                verdicts[c.verdict] = verdicts.get(c.verdict, 0) + 1
            return {
                "candidates": len(self.candidates),
                "campaigns": len(self.campaigns),
                "verdicts": verdicts,
                "generated_at": datetime.now(UTC).isoformat(),
            }


store = Store()
