"""Background job execution for long-running ingestion and crawl work.

Jobs run on a small thread pool and record their lifecycle (queued -> running ->
done/failed), progress counters and resulting candidate ids in the store, so they
can be polled through ``GET /jobs/{id}`` and survive a process restart.

Set ``JOBS_INLINE=1`` to execute jobs synchronously in the calling thread; the test
suite uses this for deterministic assertions.
"""
from __future__ import annotations

import logging
import os
import threading
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

from app.config import get_settings
from app.schemas import Job, JobProgress
from app.store import store

logger = logging.getLogger(__name__)


def _is_expected_failure(exc: Exception) -> bool:
    """Unreachable hosts, dead links and malformed downloads are routine for phishing
    infrastructure; they are recorded on the job without a stack trace."""
    try:
        import httpx

        if isinstance(exc, httpx.HTTPError):
            return True
    except ImportError:  # pragma: no cover
        pass
    from app.services.apps import ApkError

    return isinstance(exc, (ConnectionError, TimeoutError, ApkError, ValueError))


class JobContext:
    """Handle passed to a job body to report progress and results."""

    def __init__(self, job: Job) -> None:
        self._job = job
        self._lock = threading.Lock()

    def set_total(self, total: int) -> None:
        with self._lock:
            self._job.progress.total = total
            store.save_job(self._job)

    def advance(self, ok: bool = True, candidate_id: str | None = None) -> None:
        with self._lock:
            self._job.progress.processed += 1
            if not ok:
                self._job.progress.failed += 1
            if candidate_id and candidate_id not in self._job.candidate_ids:
                self._job.candidate_ids.append(candidate_id)
            store.save_job(self._job)


JobBody = Callable[[JobContext], None]


class JobManager:
    def __init__(self, workers: int | None = None) -> None:
        self._workers = workers or get_settings().job_workers
        self._executor: ThreadPoolExecutor | None = None
        self._lock = threading.Lock()

    @property
    def inline(self) -> bool:
        return os.getenv("JOBS_INLINE", "").lower() in {"1", "true", "yes", "on"}

    def _pool(self) -> ThreadPoolExecutor:
        with self._lock:
            if self._executor is None:
                self._executor = ThreadPoolExecutor(max_workers=self._workers, thread_name_prefix="upi-job")
            return self._executor

    def submit(self, kind: str, params: dict, body: JobBody) -> Job:
        job = Job(id=uuid.uuid4().hex[:12], kind=kind, status="queued", params=params,
                  progress=JobProgress(), created_at=datetime.now(UTC))
        store.save_job(job)
        if self.inline:
            self._run(job, body)
        else:
            self._pool().submit(self._run, job, body)
        return store.get_job(job.id) or job

    def _run(self, job: Job, body: JobBody) -> None:
        job.status = "running"
        job.started_at = datetime.now(UTC)
        store.save_job(job)
        try:
            body(JobContext(job))
            job.status = "done"
        except Exception as exc:  # noqa: BLE001 - a failing job must be recorded, not crash the worker
            if _is_expected_failure(exc):
                logger.warning("job %s (%s) failed: %s: %s", job.id, job.kind, type(exc).__name__, exc)
            else:
                logger.exception("job %s (%s) failed", job.id, job.kind)
            job.status = "failed"
            job.error = f"{type(exc).__name__}: {exc}"
        job.finished_at = datetime.now(UTC)
        store.save_job(job)

    def shutdown(self) -> None:
        with self._lock:
            if self._executor is not None:
                self._executor.shutdown(wait=False, cancel_futures=True)
                self._executor = None


jobs = JobManager()


class CrawlScheduler:
    """Triggers a certificate-transparency crawl job every N minutes (0 disables)."""

    def __init__(self, interval_minutes: int, trigger: Callable[[], object]) -> None:
        self.interval = max(0, interval_minutes) * 60
        self._trigger = trigger
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if not self.interval or self._thread is not None:
            return
        self._thread = threading.Thread(target=self._loop, name="upi-crawl-scheduler", daemon=True)
        self._thread.start()
        logger.info("crawl scheduler started (every %d s)", self.interval)

    def _loop(self) -> None:
        while not self._stop.wait(self.interval):
            try:
                self._trigger()
            except Exception:  # noqa: BLE001 - keep the scheduler alive
                logger.exception("scheduled crawl failed to start")

    def stop(self) -> None:
        self._stop.set()
