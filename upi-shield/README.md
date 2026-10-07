# UPI Shield (backend)

Anti-phishing / UPI Shield detection backend: ingests suspicious URLs and messages,
scores them through a staged pipeline (lexical URL features -> visual/structural
similarity -> behavioural DOM analysis -> infrastructure enrichment), clusters
related clones into campaigns over shared infrastructure, and generates automated
takedown reports. FastAPI + in-memory store; everything runs offline/deterministically
(no heavy ML, no GPU, optional network stages degrade gracefully).

## Run the backend

    cd backend
    python -m venv .venv && . .venv/bin/activate
    pip install -r requirements.txt
    uvicorn app.main:app --reload      # open http://localhost:8000/docs
    python -m pytest -q                # 42 tests, all offline

Demo data is seeded on startup (2 campaigns). Key endpoints: `/health`,
`/ingest/url`, `/ingest/message`, `/candidates`, `/campaigns`, `/graph`,
`/reports/takedown`, `/eval/metrics`.

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
