FROM python:3.12-slim

# Set WITH_BROWSER=false for a smaller image without headless Chromium; the fetcher
# then falls back to plain HTTP and visual matching uses favicon and page structure.
ARG WITH_BROWSER=true

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    UPI_SHIELD_DB=/srv/data/upi_shield.db \
    UPI_SHIELD_EVIDENCE_DIR=/srv/data/evidence

WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
 && if [ "$WITH_BROWSER" = "true" ]; then playwright install --with-deps chromium-headless-shell \
      && rm -rf /var/lib/apt/lists/*; fi

COPY app ./app
# Ship the committed evaluation metrics so GET /eval/metrics serves real numbers.
COPY eval ./eval

RUN useradd --create-home --uid 10001 shield && mkdir -p /srv/data && chown -R shield /srv/data
USER shield
VOLUME ["/srv/data"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
