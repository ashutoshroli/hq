# UPI Shield (backend skeleton)

    cd backend && pip install -r requirements.txt
    uvicorn app.main:app --reload      # open http://localhost:8000/docs
    pytest

Demo data is seeded on startup (2 campaigns). Real stages plug into `app/services/pipeline.py`.
Eval endpoint returns placeholder zeros until `eval/evaluate.py` writes real numbers.
