"""Demo data so the dashboard has something to show before the real crawler works.
Two campaigns: one linked by a shared UPI ID + favicon, one by a shared IP + phone."""
from datetime import UTC, datetime, timedelta

from app.schemas import Candidate, Entity, Signal
from app.store import store


def _c(i, url, domain, brand, score, ents, minutes_ago, source="ct_log"):
    return Candidate(
        id=f"seed{i}", url=url, domain=domain, source=source,
        first_seen=datetime.now(UTC) - timedelta(minutes=minutes_ago),
        risk_score=score, verdict="malicious" if score >= 0.7 else "suspicious",
        brand_matched=brand, visual_similarity=round(min(0.99, score + 0.1), 2),
        signals=[Signal(name="brand_in_unofficial_domain", weight=0.5, detail=f"'{brand}' in {domain}"),
                 Signal(name="lure_keywords", weight=0.15, detail="verify, kyc")],
        entities=[Entity(type="domain", value=domain), *ents],
    )


def seed() -> None:
    store.candidates.clear()
    fav, upi = Entity(type="favicon_hash", value="a1b2c3d4"), Entity(type="upi_id", value="rewards.help@okaxis")
    ip, ph = Entity(type="ip", value="203.0.113.7"), Entity(type="phone", value="9876543210")
    rows = [
        _c(1, "http://phonepe-kyc-verify.xyz/login", "phonepe-kyc-verify.xyz", "phonepe", 0.92, [fav, upi], 300),
        _c(2, "http://ph0nepe-update.top", "ph0nepe-update.top", "phonepe", 0.88, [fav], 200),
        _c(3, "http://paytm-cashback-claim.click", "paytm-cashback-claim.click", "paytm", 0.81, [upi], 120, "message"),
        _c(4, "http://sbi-yono-secure-login.live", "sbi-yono-secure-login.live", "sbi", 0.9, [ip, ph], 90),
        _c(5, "http://hdfc-netbanking-blocked.site", "hdfc-netbanking-blocked.site", "hdfc", 0.77, [ip], 45),
        _c(6, "http://gpay-refund-center.online", "gpay-refund-center.online", "gpay", 0.55, [], 10, "user_report"),
    ]
    for r in rows:
        store.candidates[r.id] = r
    store.recluster()
