# UPI Shield: fake UPI and payment page and app detection at scale

Backend for **Problem 11, Fake UPI and Payment Page and App Detection at Scale**
(Track 03, Anti-Phishing & UPI Shield). It discovers clones of Indian banking and
payment brands, scores them with URL, visual, behavioural and app analysis, maps the
infrastructure behind them into campaigns, and drives takedowns to completion.

## Requirements coverage

| Requirement | Implementation |
|-------------|----------------|
| Crawler for suspicious pages and apps from certificate logs, messages and reports | CT discovery via the crt.sh PostgreSQL replica (`POST /crawl/ct`, optional schedule); SMS/WhatsApp extraction (`POST /ingest/message`), including link-less lures stored as message candidates; user reports and OpenPhish/URLhaus feeds (`/ingest/url`, `/ingest/batch`, `/ingest/feed`); APK upload/download, plus APK links from messages, reports, feeds and phishing pages routed to app analysis (`/ingest/app`, `/ingest/app/url`) |
| Visual and behavioural similarity engine matching clones to genuine brands | Headless-Chromium screenshots compared with genuine brand pages by perceptual hashing; favicon and app-icon matching; brand identification from appearance alone; DOM behaviour (UPI PIN/OTP/card fields, cross-domain posts, obfuscated JS, APK pushes); APK static analysis |
| Infrastructure graph linking domains, hosts, wallets and phone numbers into campaigns | Enrichment (IP, ASN, certificate, registrar, RDAP age, abuse contacts); union-find clustering over UPI handles, phones, Telegram ids, favicons, analytics ids, C2 hosts and signing certificates, with CDN-aware and weak-evidence rules; `GET /graph`, `GET /pivot` |
| Analyst dashboard and automated takedown report generator | Dashboard summary API, review queue with audit trail, routed takedown plans with verified contacts, tracked takedown cases with liveness re-checks, reports for nine recipient types, and Markdown/JSON/STIX 2.1/ZIP evidence exports |
| End-to-end detection pipeline | `python -m eval.live_demo` (live, see below) and `python -m eval.campaign_demo` (offline) |
| Precision/recall on a labelled sample | Real-world held-out benchmark: **precision 0.875, recall 0.778, FPR 0.23%** (see Evaluation) |
| Campaign-clustering demo | `python -m eval.campaign_demo`, plus the live demo |
| Key challenges (visual similarity, URL and behavioural analysis, evasion) | Screenshot similarity calibrated against cross-brand separation; homographs, typosquats, combosquats, shorteners, free hosting, cloaking, mobile-only kits, bot walls, new domains |

## Quick start

    cd backend
    python -m venv .venv && . .venv/bin/activate
    pip install -r requirements.txt -r requirements-dev.txt
    playwright install chromium          # screenshots; optional, falls back to HTTP
    uvicorn app.main:app --reload        # API docs at http://localhost:8000/docs
    python -m pytest                     # offline test suite
    python -m eval.evaluate              # precision / recall
    python -m eval.campaign_demo         # offline clustering + takedown demo
    python -m eval.live_demo --limit 30  # live end-to-end run (network)

Or with Docker: `docker compose up --build`, which serves the API on :8000 and the
**analyst dashboard on http://localhost:8080** (set `ANALYZE_FETCH=1` for live analysis).
The dashboard lives in `frontend/` (see `frontend/README.md`).

Demo data (two campaigns) is seeded on first start when the store is empty. Data is
persisted to `backend/data/upi_shield.db` (override with `UPI_SHIELD_DB`). The default
configuration is offline and deterministic; every network stage degrades gracefully.

## API overview

| Area | Endpoints |
|------|-----------|
| System | `GET /health`, `GET /stats`, `POST /admin/seed` |
| Ingestion | `POST /ingest/url`, `POST /ingest/message`, `POST /ingest/batch`, `POST /ingest/feed`, `POST /ingest/app`, `POST /ingest/app/url`, `POST /crawl/ct` |
| Jobs | `GET /jobs`, `GET /jobs/{id}` |
| Analysis | `GET /candidates` (filters: `min_score`, `verdict`, `kind`, `brand`, `source`, `campaign_id`, `q`, `limit`, `offset`), `GET /candidates/{id}`, `GET /campaigns`, `GET /campaigns/{id}`, `GET /graph`, `GET /pivot` |
| Workflow | `POST /candidates/{id}/review`, `GET /audit`, `GET /campaigns/{id}/takedown-plan`, `POST /takedowns`, `GET /takedowns`, `GET`/`PATCH /takedowns/{id}`, `POST /takedowns/{id}/recheck`, `GET /dashboard/summary` |
| Reporting | `POST /reports/takedown`, `GET /campaigns/{id}/export?format=markdown\|json\|stix\|zip`, `GET /evidence/{name}`, `GET /eval/metrics` |

Batch, feed and crawl requests return `202 Accepted` with a `job_id`; poll
`GET /jobs/{id}` for status (`queued`, `running`, `done`, `failed`) and progress.
Re-ingesting a URL that is already known updates the existing candidate (merged
entities, incremented `sightings`, refreshed `last_seen`) instead of duplicating it.

## Analyst workflow and takedowns

1. **Triage:** `GET /dashboard/summary` returns totals, detections per day, top
   signals, brand breakdown, takedown SLA and the highest-risk unreviewed candidates.
2. **Review:** `POST /candidates/{id}/review` with `confirmed`, `false_positive` or
   `escalated`. False positives leave campaigns and reports. Decisions survive
   re-analysis, and every action is written to the audit trail (`GET /audit`).
3. **Plan:** `GET /campaigns/{id}/takedown-plan` routes each target to the party that
   can act on it, using only verified contacts:
   * registrar abuse contacts (RDAP) and hosting abuse contacts (RIPEstat);
   * platform abuse channels for free hosting (Cloudflare Pages, Vercel, Netlify,
     GitHub Pages, Firebase, …);
   * phishing-report addresses published by the brands themselves;
   * NPCI for UPI handles, Sanchar Saathi for fraud phone numbers, Google Play Protect
     for apps, Safe Browsing, CERT-In (`incident@cert-in.org.in`) and the National
     Cyber Crime Reporting Portal (cybercrime.gov.in, helpline 1930).

   When no verified contact exists, the item is marked `lookup_required` instead of
   guessing.
4. **Track:** `POST /takedowns` opens a case with the generated report;
   `PATCH /takedowns/{id}` moves it through `drafted → sent → acknowledged → resolved`
   (or `rejected`). `POST /takedowns/{id}/recheck` probes every target and resolves the
   case automatically once all are offline.
5. **Share:** `GET /campaigns/{id}/export` produces a Markdown dossier, JSON, a
   **STIX 2.1** bundle for CERT-In, ISACs or a TIP, or a ZIP evidence package
   (dossier, data, STIX, one report per recipient, and screenshots).

## Discovery sources

* **Certificate-transparency logs** (`POST /crawl/ct`): queries crt.sh for currently
  valid certificates that mention a monitored brand keyword and keeps hosts whose
  registered domain is not owned by the brand. The public crt.sh PostgreSQL replica is
  used first (it is far more reliable than the JSON API); the JSON API is the fallback.
  Set `CRAWL_INTERVAL_MINUTES` to crawl on a schedule.
* **Messages** (`POST /ingest/message`): URLs (including bare domains such as
  `sbi-kyc.top/update`), UPI handles, phone numbers and Telegram handles are extracted
  from SMS/WhatsApp text and attached to the analysed URLs as linking entities.
  Messages **without any link**, which ask the victim to pay a mule UPI handle or call
  a fake helpline, are stored as `kind: "message"` candidates. They are scored from the
  lure wording (brand invoked, brand-impersonating UPI handle, payment or credential
  request, KYC or blocking threats, urgency, rewards). Their indicators reach the graph
  and campaigns, and card or account numbers are masked in the stored excerpt.
* **APK links anywhere** (messages, reports, feeds, redirects, or files served without
  an `.apk` extension) are queued for app analysis, and the job ids are returned as
  `job_ids`. The resulting app carries the message's indicators and the distribution
  host, so the message, the download site and the app join one campaign.
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

### Infrastructure graph and campaigns (`services/graph.py`, `services/clustering.py`)

Enrichment resolves each host to its IP, network (ASN, holder and prefix via RIPEstat),
TLS certificate, registrar and registration date (RDAP), together with the **hosting
and registrar abuse contacts** used for takedowns (`Candidate.infrastructure`).

Campaigns are formed by union-find over entities that identify an operator: UPI
handles, phone numbers, Telegram handles and bot ids, favicons, analytics ids, C2 or
landing hosts, app package names, APK hashes and signing certificates.

* **Weak entities** (registrar, ASN) are recorded as evidence but never merge
  candidates on their own.
* **CDN and shared hosting:** when a site sits on a CDN or shared-hosting network
  (Cloudflare, Akamai, Fastly, GitHub, the big clouds, …), its IP and certificate are
  shared with unrelated customers and do not link it to anything.
* **Shared public infrastructure** (URL shorteners, hosting-platform apex domains,
  brand-owned domains and the AOSP test signing key) never links.

`GET /graph` returns sites and apps as nodes enriched with candidate facts (risk,
verdict, brand, kind), plus entity nodes. Entity nodes carry `linking` (whether the
value can merge campaigns) and `degree` (how many candidates use it). Edges carry
typed relations such as `collects_payments_to`, `hosted_on`, `signed_with` and
`communicates_with`. `GET /pivot?type=upi_id&value=…` lists every candidate that uses
a given entity.

### Optional network stages & graceful degradation

Page fetching (`services/fetcher.py`) and enrichment are **opt-in** and OFF by default
(`ANALYZE_FETCH=1` to enable at runtime, or `do_fetch=True` per call). The optional
Playwright render path is used only when Playwright is installed and a browser
launches, and always falls back to the stdlib httpx fetch. When a page cannot be
fetched or a resolver fails, the pipeline keeps the lexical URL verdict and the
visual/behaviour stages return empty — nothing raises, so the detector still runs.

## Evaluation (precision / recall)

    cd backend && python -m eval.evaluate   # writes eval/metrics.json and eval/benchmark_report.md

Two complementary evaluations are reported. `GET /eval/metrics` serves both
(`stages` = controlled sample, `benchmarks` = real-world sample).

### 1. Real-world benchmark (held-out, external labels)

`eval/data/benchmark.csv`, built by `python -m eval.build_benchmark`:

* **Positives:** hosts reported as active phishing by
  [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database) and
  [OpenPhish](https://openphish.com/) whose hostname references a monitored brand. Each
  is annotated with the brand it impersonates in `eval/data/benchmark_targets.csv`;
  hosts attacking other organisations (for example `upiholdlogin…` targets the Uphold
  exchange, `sbisec…` targets SBI Securities Japan) are excluded as out of scope.
* **Negatives:** every [Tranco](https://tranco-list.eu/) top-1M domain containing a
  brand keyword (hard negatives such as `famousbirthdays.com` or `catholicicing.com`),
  plus a fixed random sample of 1,500 Tranco top-100k domains. Brand-owned domains are
  excluded so the brand catalogue cannot leak labels.
* Host-level and URL features only (the decision the CT crawler makes for a newly
  certified name), so it is fully offline and reproducible.
* Hosts are split into `dev` and `test` by hash. Rules were tuned by inspecting
  **dev errors only**; `test` is the reported number.

| split | n | positives | negatives | precision | recall | F1 | false-positive rate |
|-------|---|-----------|-----------|-----------|--------|----|---------------------|
| **test** | 1360 | 27 | 1333 | **0.875** | **0.778** | **0.824** | 0.23% |
| dev | 1373 | 28 | 1345 | 0.920 | 0.821 | 0.868 | 0.15% |

The positive class is small (95% Wilson intervals on test: precision 0.69–0.96,
recall 0.59–0.89). Every error is listed in `eval/benchmark_report.md`. Remaining misses
are mostly hosts whose only brand evidence is a short keyword without banking context
(`upipayment.in`, `iciciphone.com`). The page-level stages below recover such cases
from screenshots and DOM behaviour when the page is reachable.

### 2. Controlled page-level sample (all stages)

`eval/dataset.py` holds 31 hand-built items with canned page fixtures (credential-
harvesting DOMs, reused favicons and analytics IDs). It exercises every pipeline stage
offline, which a URL list cannot do. It is a functional regression test, not an
estimate of real-world accuracy.

| stage        | precision | recall | f1    |
|--------------|-----------|--------|-------|
| url_only     | 1.000     | 0.938  | 0.968 |
| url+visual   | 1.000     | 0.938  | 0.968 |
| full         | 1.000     | 1.000  | 1.000 |

## Campaign-clustering demo

    python -m eval.campaign_demo   # offline, deterministic

Ingests the labelled phishing items through the pipeline + store, clusters them, and
prints the discovered campaigns (members + shared-infrastructure evidence) plus an
auto-generated takedown report for one campaign (two campaigns on the sample: a
PhonePe/Paytm cluster linked by a reused favicon + UPI handle, and an SBI/HDFC cluster
linked by a shared host IP + callback phone).

## Live end-to-end demo

`python -m eval.live_demo` pulls currently reported phishing URLs that reference
monitored brands (one URL per host), renders each page, runs every stage, clusters the
results and prints the takedown plan for the largest campaign. It uses a throwaway
database, so analyst data is never touched.

Sample run on 2026-10-07, 30 hosts from Phishing.Database:

* 22 of 30 hosts were flagged. The 8 unflagged hosts include
  `clctab.axisbank.co.in` (a genuine Axis Bank host wrongly listed in the feed) and
  hosts with no brand evidence left once their pages were gone.
* Only 1 of the 22 flagged hosts still served content. The rest had already been
  disabled by their platforms: Vercel answered HTTP 451 `DEPLOYMENT_DISABLED`, and
  Firebase and 000webhost served "Site Not Found". The pipeline records this as
  `live: false` with a `site_offline` signal and keeps the error-page screenshot as
  takedown evidence.
* No campaigns formed in this sample. With the kits offline, no page content (UPI
  handles, phones, analytics ids) remained to link them, and the CDN-aware rules
  correctly refused to merge sites that merely share Vercel or Cloudflare edge IPs.

This also shows why the CT crawler matters: feeds report pages after victims have
seen them, whereas certificate logs reveal lookalike names when they are certified,
often before the page goes live.

## Known limitations

* **Small positive class in the benchmark.** Public feeds contain few hosts that
  impersonate Indian payment brands (27 in the held-out split), so the confidence
  intervals are wide. The benchmark is host-level and evaluates URL features only;
  page-level stages are covered by the controlled sample and the live demo.
* **Brand-keyword dependence of URL scoring.** Hosts that never mention a brand are
  caught only by the visual stage, which requires the page to be reachable.
* **Reference library freshness.** Screenshot and icon references must be rebuilt
  (`python -m app.tools.build_brand_refs`) when a brand redesigns its site. HDFC Bank
  blocks desktop crawlers, so only its mobile view is referenced.
* **Unverified contacts are not guessed.** Brand phishing-report addresses are
  included only where published on the brand's own site (ICICI, HDFC); other brands
  show `lookup_required`.
* **Dashboard in progress.** The `frontend/` dashboard currently provides the overview
  and settings pages; detections, ingestion, campaigns and takedown screens follow.
