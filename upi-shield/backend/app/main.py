import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import router
from app.config import get_settings
from app.jobs import CrawlScheduler, jobs
from app.seed import seed
from app.services import ingest
from app.store import store

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("upi_shield")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    settings = get_settings()
    if settings.seed_demo and not store.candidates:
        seed()
        logger.info("seeded demo data (%d candidates)", len(store.candidates))
    scheduler = CrawlScheduler(
        settings.crawl_interval_minutes,
        lambda: jobs.submit("crawl_ct", {"scheduled": True}, ingest.crawl_job(None, None)),
    )
    scheduler.start()
    yield
    scheduler.stop()
    jobs.shutdown()


app = FastAPI(
    title="UPI Shield API",
    version="0.2.0",
    description="Detection, campaign clustering and takedown reporting for fake UPI and payment pages.",
    lifespan=lifespan,
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
app.include_router(router)
