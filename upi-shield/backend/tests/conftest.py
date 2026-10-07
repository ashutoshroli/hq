"""Shared test configuration.

Environment variables are set before any ``app`` module is imported so the store
is ephemeral (in-memory SQLite), jobs run inline, and nothing touches the network.
"""
import os

os.environ.setdefault("UPI_SHIELD_DB", ":memory:")
os.environ.setdefault("UPI_SHIELD_EVIDENCE_DIR", os.path.join(os.path.dirname(__file__), ".evidence"))
os.environ.setdefault("JOBS_INLINE", "1")
os.environ.setdefault("SEED_DEMO", "1")
os.environ.pop("ANALYZE_FETCH", None)
os.environ.pop("UPI_SHIELD_API_KEY", None)

import pytest  # noqa: E402

from app.seed import seed  # noqa: E402


@pytest.fixture(autouse=True)
def demo_store():
    """Start every test from the seeded demo dataset (two campaigns)."""
    seed()
    yield
