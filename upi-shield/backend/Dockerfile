FROM python:3.12-slim
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
# Ship the real evaluation metrics so GET /eval/metrics serves committed
# precision/recall in the container (not the is_placeholder=true fallback).
COPY eval ./eval
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
