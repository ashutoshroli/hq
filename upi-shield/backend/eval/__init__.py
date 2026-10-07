"""UPI Shield evaluation package.

Contains the labelled sample dataset and the offline, deterministic evaluation
harness that measures precision/recall/F1 of the detection pipeline across three
stage configurations (url_only, url+visual, full). See ``eval/evaluate.py`` and
``eval/campaign_demo.py`` for the entrypoints (``python -m eval.evaluate`` /
``python -m eval.campaign_demo``).
"""
