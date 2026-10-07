"""Runtime configuration, read once from environment variables.

Every setting has a safe default so the service runs out of the box for a demo,
while deployments can tune behaviour without code changes.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent


def _flag(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def _list(name: str, default: list[str]) -> list[str]:
    raw = os.getenv(name)
    if not raw:
        return list(default)
    return [part.strip() for part in raw.split(",") if part.strip()]


DEFAULT_CRAWL_KEYWORDS = ["phonepe", "paytm", "gpay", "bhim", "sbi", "hdfc", "icici", "axisbank"]


@dataclass(frozen=True)
class Settings:
    # Storage. Use ":memory:" for an ephemeral store (the test suite does this).
    database_path: str = field(default_factory=lambda: os.getenv(
        "UPI_SHIELD_DB", str(BACKEND_DIR / "data" / "upi_shield.db")))
    # Directory where captured screenshots and other evidence artefacts are written.
    evidence_dir: str = field(default_factory=lambda: os.getenv(
        "UPI_SHIELD_EVIDENCE_DIR", str(BACKEND_DIR / "data" / "evidence")))
    # Seed the demo campaigns on startup when the store is empty.
    seed_demo: bool = field(default_factory=lambda: _flag("SEED_DEMO", True))
    # Live page fetch + infrastructure enrichment (network). Off by default.
    analyze_fetch: bool = field(default_factory=lambda: _flag("ANALYZE_FETCH", False))
    # Render pages in headless Chromium (screenshots for visual matching) when fetching.
    render_pages: bool = field(default_factory=lambda: _flag("RENDER_PAGES", True))
    # Background worker pool used by asynchronous ingestion and crawl jobs.
    job_workers: int = field(default_factory=lambda: max(1, _int("JOB_WORKERS", 4)))
    # Brand keywords queried against certificate-transparency logs.
    crawl_keywords: list[str] = field(default_factory=lambda: _list("CRAWL_KEYWORDS", DEFAULT_CRAWL_KEYWORDS))
    # Periodic crawl interval in minutes; 0 disables the scheduler.
    crawl_interval_minutes: int = field(default_factory=lambda: _int("CRAWL_INTERVAL_MINUTES", 0))
    # Upper bound on hosts analysed per crawl job, to keep jobs bounded.
    crawl_max_hosts: int = field(default_factory=lambda: _int("CRAWL_MAX_HOSTS", 200))
    # Optional shared secret. When set, mutating endpoints require the X-API-Key header.
    api_key: str | None = field(default_factory=lambda: os.getenv("UPI_SHIELD_API_KEY") or None)


def get_settings() -> Settings:
    """Return a fresh Settings snapshot (cheap; lets tests change env between cases)."""
    return Settings()
