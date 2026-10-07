from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import router
from app.seed import seed

app = FastAPI(title="UPI Shield API", version="0.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
app.include_router(router)


@app.on_event("startup")
def _seed_on_start() -> None:
    seed()  # remove once real ingestion is the demo path
