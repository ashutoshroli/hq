# UPI Shield (backend)

Anti-phishing / UPI Shield detection backend: ingests suspicious URLs and messages,
scores them through a staged pipeline (lexical URL features -> visual/structural
similarity -> behavioural DOM analysis -> infrastructure enrichment), clusters
related clones into campaigns over shared infrastructure, and generates automated
takedown reports. FastAPI with a SQLite-backed store; the default configuration runs
offline and deterministically, and every network stage degrades gracefully.

## Run the backend

    cd backend
    python -m venv .venv && . .venv/bin/activate
    pip install -r requirements.txt
    uvicorn app.main:app --reload      # open http://localhost:8000/docs
    pip install -r requirements-dev.txt
    python -m pytest                   # offline test suite

Demo data (two campaigns) is seeded on first start when the store is empty. Data is
persisted to `backend/data/upi_shield.db` (override with `UPI_SHIELD_DB`).

## API overview

| Area | Endpoints |
|------|-----------|
| System | `GET /health`, `GET /stats`, `POST /admin/seed` |
| Ingestion | `POST /ingest/url`, `POST /ingest/message`, `POST /ingest/batch`, `POST /ingest/feed`, `POST /crawl/ct` |
| Jobs | `GET /jobs`, `GET /jobs/{id}` |
| Analysis | `GET /candidates` (filters: `min_score`, `verdict`, `brand`, `source`, `campaign_id`, `q`, `limit`, `offset`), `GET /candidates/{id}`, `GET /campaigns`, `GET /campaigns/{id}`, `GET /graph` |
| Reporting | `POST /reports/takedown`, `GET /eval/metrics` |

Batch, feed and crawl requests return `202 Accepted` with a `job_id`; poll
`GET /jobs/{id}` for status (`queued`, `running`, `done`, `failed`) and progress.
Re-ingesting a URL that is already known updates the existing candidate (merged
entities, incremented `sightings`, refreshed `last_seen`) instead of duplicating it.

## Discovery sources

* **Certificate-transparency logs** (`POST /crawl/ct`): queries crt.sh for currently
  valid certificates that mention a monitored brand keyword and keeps hosts whose
  registered domain is not owned by the brand. The public crt.sh PostgreSQL replica is
  used first (it is far more reliable than the JSON API); the JSON API is the fallback.
  Set `CRAWL_INTERVAL_MINUTES` to crawl on a schedule.
* **Messages** (`POST /ingest/message`): URLs, UPI handles, phone numbers and Telegram
  handles are extracted from SMS/WhatsApp text and attached as linking entities.
* **Reports and feeds** (`POST /ingest/url`, `POST /ingest/batch`, `POST /ingest/feed`):
  analyst or user reports, and the OpenPhish and URLhaus public feeds (filtered to
  URLs that reference a monitored brand by default).

## Configuration

| Variable | Default | Purpose |
|----------|---------|---------|
| `UPI_SHIELD_DB` | `backend/data/upi_shield.db` | SQLite path (`:memory:` for an ephemeral store) |
| `ANALYZE_FETCH` | `0` | Fetch pages live and run enrichment (network) |
| `SEED_DEMO` | `1` | Seed demo campaigns when the store is empty |
| `JOB_WORKERS` | `4` | Background worker threads |
| `CRAWL_KEYWORDS` | monitored brands | Comma-separated CT search keywords |
| `CRAWL_INTERVAL_MINUTES` | `0` | Scheduled CT crawl interval (0 disables) |
| `CRAWL_MAX_HOSTS` | `200` | Maximum hosts analysed per crawl job |
| `UPI_SHIELD_API_KEY` | unset | When set, mutating endpoints require `X-API-Key` |

## Detection stages

1. **URL features** (`services/url_features.py`) — lexical scoring on every URL:
   brand-in-unofficial-domain, homoglyph normalisation, suspicious TLDs, punycode,
   lure keywords, raw-IP hosts. Always on, no network.
2. **Visual / structural similarity** (`services/visual.py`) — lightweight,
   offline. Favicon-hash reuse + perceptual aHash (Pillow, optional) when an image
   is available, otherwise a pure-python title/vocabulary/DOM-marker comparison
   against a small brand index.
3. **Behaviour** (`services/behaviour.py`) — flags credential-harvesting DOMs:
   UPI PIN/OTP/CVV/card inputs, cross-domain form actions, obfuscated inline JS,
   credential-harvesting text.
4. **Enrichment** (`services/enrichment.py`) — resolves host -> ip/asn/cert/registrar
   and scrapes analytics IDs. Each lookup is an injectable resolver; defaults use the
   network but return `None` on failure, so the stage degrades gracefully offline.

Campaign clustering (`services/clustering.py`) unions candidates via shared **strong**
entities (ip, cert_fingerprint, upi_id, phone, telegram, favicon_hash, analytics_id);
registrar/asn are **weak** (recorded as evidence but never merge alone).

### Optional network stages & graceful degradation

Page fetching (`services/fetcher.py`) and enrichment are **opt-in** and OFF by default
(`ANALYZE_FETCH=1` to enable at runtime, or `do_fetch=True` per call). The optional
Playwright render path is used only when Playwright is installed and a browser
launches, and always falls back to the stdlib httpx fetch. When a page cannot be
fetched or a resolver fails, the pipeline keeps the lexical URL verdict and the
visual/behaviour stages return empty — nothing raises, so the detector still runs.

## Evaluation (precision / recall)

A labelled sample (`backend/eval/dataset.py`, 31 items: lookalike phishing URLs with
canned credential-harvesting page fixtures + genuine brand/legit domains) is scored by
the real engines across three cumulative stage configurations. An item is predicted
**malicious** when its cumulative score reaches the product cutoff (`>= 0.70`).

    cd backend && . .venv/bin/activate
    python -m eval.evaluate        # writes eval/metrics.json, prints the table below

Achieved on the committed sample (regenerate deterministically with the command above):

| stage        | precision | recall | f1    |
|--------------|-----------|--------|-------|
| url_only     | 1.000     | 0.750  | 0.857 |
| url+visual   | 1.000     | 0.875  | 0.933 |
| full         | 1.000     | 1.000  | 1.000 |

Each stage adds recall while holding precision at 1.000: URL features catch the
obvious lookalikes, visual similarity recovers weak-URL clones that serve a
brand-echoing page, and behaviour pushes raw-IP / punycode clones over the line via
their credential-harvesting DOM. `GET /eval/metrics` serves `eval/metrics.json`
(`is_placeholder=false`) when present and falls back to a placeholder when absent.

## Campaign-clustering demo

    python -m eval.campaign_demo   # offline, deterministic

Ingests the labelled phishing items through the pipeline + store, clusters them, and
prints the discovered campaigns (members + shared-infrastructure evidence) plus an
auto-generated takedown report for one campaign (two campaigns on the sample: a
PhonePe/Paytm cluster linked by a reused favicon + UPI handle, and an SBI/HDFC cluster
linked by a shared host IP + callback phone).
