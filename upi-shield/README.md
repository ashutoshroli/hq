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
| Ingestion | `POST /ingest/url`, `POST /ingest/message`, `POST /ingest/batch`, `POST /ingest/feed`, `POST /ingest/app`, `POST /ingest/app/url`, `POST /crawl/ct` |
| Jobs | `GET /jobs`, `GET /jobs/{id}` |
| Analysis | `GET /candidates` (filters: `min_score`, `verdict`, `kind`, `brand`, `source`, `campaign_id`, `q`, `limit`, `offset`), `GET /candidates/{id}`, `GET /campaigns`, `GET /campaigns/{id}`, `GET /graph` |
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
| `RENDER_PAGES` | `1` | Render with headless Chromium and capture screenshots when fetching |
| `UPI_SHIELD_EVIDENCE_DIR` | `backend/data/evidence` | Where screenshots are stored |
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
2. **Visual similarity** (`services/visual.py`, `services/imaging.py`) — pages are
   rendered in headless Chromium (desktop viewport) and the screenshot is fingerprinted
   with a DCT perceptual hash, a gradient hash and a brand-colour histogram (Pillow +
   numpy, no ML models). Fingerprints are compared with screenshots and favicons of the
   genuine brand sites in `app/data/brand_refs.json`. Because the comparison does not
   depend on the URL, a clone hosted on an unbranded domain is still attributed to the
   brand it imitates. On the committed library, different brands never exceed 0.63
   screenshot similarity, while re-encoded, cropped or banner-modified copies of a
   brand page score at least 0.86 (match threshold: 0.85). Title, vocabulary and DOM
   markers provide a structural fallback when no screenshot is available. Screenshots
   are stored as evidence and served from `GET /evidence/{name}`.

   Rebuild the reference library after a brand redesign:

       playwright install chromium
       python -m app.tools.build_brand_refs            # or --brand phonepe

3. **Behaviour** (`services/behaviour.py`) — flags credential-harvesting DOMs:
   UPI PIN/OTP/CVV/card inputs, cross-domain form actions, obfuscated inline JS,
   credential-harvesting prompts. Obfuscation and prompts carry full weight only in a
   phishing context (credential inputs present or brand impersonation detected), and
   pages whose final URL is on a brand-owned domain are never penalised.
4. **Enrichment** (`services/enrichment.py`) — resolves host -> ip/asn/cert/registrar
   and scrapes analytics IDs. Each lookup is an injectable resolver; defaults use the
   network but return `None` on failure, so the stage degrades gracefully offline.

### Fake app detection (`services/apps.py`)

Fake banking and UPI apps are spread as sideloaded APKs. `POST /ingest/app` (upload) and
`POST /ingest/app/url` (download) analyse an APK statically, without executing it:

* **Identity:** package name, label, version, and the v1/v2/v3 signing-certificate SHA-256.
* **Impersonation:** a brand named or typosquatted in the label or package, an icon
  matching the genuine app's Google Play icon (reference icons are in
  `brand_refs.json`), or an official package name signed with a foreign certificate.
* **Capabilities:** SMS interception, accessibility abuse, overlays, notification access,
  call forwarding, silent installs, and a hidden launcher icon. These combine into a
  `banking_trojan_profile` signal. Capabilities alone are capped below "malicious".
* **Infrastructure:** C2 hosts, UPI handles, phone numbers, Telegram links and bot ids
  are read from DEX strings and assets. They become linking entities, so an app joins
  the campaign of the phishing pages it talks to. Phishing pages that offer an `.apk`
  are flagged, and the APK is fetched and analysed automatically when fetching is on.

App candidates have `kind: "app"`, `url: android://<package>?sha256=…` and an `app`
summary. `POST /reports/takedown` with recipient `app_store` produces a Google Play /
Play Protect report.

### Evasion tactics (`services/evasion.py`)

| Tactic | Detection |
|--------|-----------|
| IDN homographs (`pаytm.com` with a Cyrillic `а`) | Punycode is decoded and confusable characters are mapped to a Latin skeleton before brand matching; mixed-script labels are flagged |
| Character substitution (`ph0nepe`, `rn` for `m`) | Digit homoglyphs and multi-character tricks are normalised |
| Typosquatting (`phonpe`, `paytn`, `axisbnak`) | Brand keywords within one edit, with guards against ordinary words such as `payment` |
| Official domain as a prefix (`phonepe.com.verify-user.top`) | Flagged in addition to the brand match |
| URL shorteners and redirectors | The landing page is scored as well, and its domain becomes an entity |
| Free hosting and tunnels (`*.web.app`, `*.ngrok-free.app`, ...) | Flagged as disposable infrastructure |
| Cloaking | The page is also requested with a mobile browser and a search-crawler user agent; a crawler redirect away, error, or decoy content is flagged when the page impersonates a brand or collects credentials |
| Mobile-only kits | Behaviour analysis also runs on the mobile view |
| Anti-bot interstitials | Reported so analysts know the content may be hidden |
| Throwaway domains | RDAP registration date: registered within 30 days (strong) or 180 days (weak) |

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
