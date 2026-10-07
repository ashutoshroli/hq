"""Analysis of SMS / WhatsApp / e-mail lures as first-class candidates.

Many payment-fraud messages contain no link at all: they ask the victim to pay a
"KYC fee" to a mule UPI handle or to call a fake support number. Those indicators
are exactly what links campaigns together, so such a message is stored as a
``kind="message"`` candidate carrying its UPI handles, phone numbers and Telegram
handles as entities, scored from the wording of the lure.

The stored text is an excerpt with long digit runs (account and card numbers that
victims sometimes include when forwarding a message) masked.
"""
from __future__ import annotations

import hashlib
import re
import uuid
from datetime import UTC, datetime

from app import brands
from app.schemas import Candidate, Entity, MessageSummary, Signal, SourceType
from app.services import evasion, url_features

EXCERPT_CHARS = 500

_URGENCY = re.compile(r"\b(today|immediately|urgent(?:ly)?|within \d+ ?(?:hours?|hrs?|minutes?|mins?)|last date|"
                      r"final (?:notice|warning)|expire[sd]?|will be (?:blocked|suspended|closed|deactivated))\b", re.I)
_ACCOUNT_THREAT = re.compile(r"\b(blocked|suspended|deactivated|frozen|closed|on hold|restricted)\b", re.I)
_KYC = re.compile(r"\b(e?kyc|pan(?: card)?|aadha?ar|update (?:your )?(?:details|account|kyc|pan)|re-?verify|"
                  r"verification)\b", re.I)
_REWARD = re.compile(r"\b(cash ?back|refund|reward(?: points)?|prize|lottery|won|bonus|gift|redeem|claim)\b", re.I)
_PAYMENT_REQUEST = re.compile(r"(?:\b(?:pay|send|transfer|deposit)\b|₹|\brs\.? ?\d|\binr\b)", re.I)
_CALLBACK = re.compile(r"\b(call|whatsapp|contact|helpline|customer care|support)\b", re.I)
_APP_INSTALL = re.compile(r"\b(install|download)\b.{0,40}\b(app|apk|application)\b|\.apk\b", re.I)
_CREDENTIAL_ASK = re.compile(r"\b(otp|upi pin|mpin|cvv|password|card number)\b", re.I)
_LONG_DIGITS = re.compile(r"\d{11,19}")


def _brands_in(text: str) -> list[str]:
    low = evasion.skeleton(text.lower())
    found = []
    for brand in brands.BRANDS.values():
        names = {brand.display_name.lower(), *brand.keywords}
        if any(re.search(rf"(?<![a-z0-9]){re.escape(name)}(?![a-z0-9])", low) for name in names):
            found.append(brand.key)
    return found


def redact(text: str) -> str:
    """Excerpt with account / card numbers masked (keeps the last four digits)."""
    masked = _LONG_DIGITS.sub(lambda m: "X" * (len(m.group()) - 4) + m.group()[-4:], text or "")
    return masked[:EXCERPT_CHARS]


def score_message(text: str, found: dict[str, list[str]]) -> tuple[float, list[Signal], str | None]:
    signals: list[Signal] = []
    mentioned = _brands_in(text)
    brand = mentioned[0] if mentioned else None
    if mentioned:
        signals.append(Signal(name="brand_mentioned", weight=0.25,
                              detail="Message invokes " + ", ".join(brands.BRANDS[b].display_name for b in mentioned)))

    for upi in found.get("upi_ids", []):
        handle = upi.split("@", 1)[0]
        hit = next((kw for kw in url_features.BRANDS if len(kw) >= 3 and kw in evasion.skeleton(handle)), None)
        if hit:
            brand = brand or brands.keyword_index()[hit]
            signals.append(Signal(name="brand_impersonating_upi_handle", weight=0.35,
                                  detail=f"UPI handle {upi} poses as {brands.BRANDS[brand].display_name}; "
                                         "banks never collect fees through personal UPI handles"))
            break
    checks = [
        (_KYC, "kyc_lure", 0.2, "Asks the victim to update KYC / PAN / Aadhaar details"),
        (_ACCOUNT_THREAT, "account_threat", 0.15, "Threatens that the account is or will be blocked"),
        (_URGENCY, "urgency", 0.1, "Creates time pressure"),
        (_REWARD, "reward_lure", 0.15, "Promises cashback, refunds or prizes"),
        (_CREDENTIAL_ASK, "credential_request", 0.25, "Asks for OTP, UPI PIN, CVV or passwords"),
        (_APP_INSTALL, "app_install_request", 0.2, "Asks the victim to install an app"),
    ]
    for pattern, name, weight, detail in checks:
        match = pattern.search(text)
        if match:
            signals.append(Signal(name=name, weight=weight, detail=f"{detail} ('{match.group(0)}')"))
    if found.get("upi_ids") and _PAYMENT_REQUEST.search(text):
        signals.append(Signal(name="payment_request_to_upi", weight=0.25,
                              detail="Requests a payment to " + ", ".join(found["upi_ids"][:3])))
    if found.get("phones") and _CALLBACK.search(text):
        signals.append(Signal(name="callback_number", weight=0.1,
                              detail="Directs the victim to call " + ", ".join(found["phones"][:3])))
    if found.get("telegram"):
        signals.append(Signal(name="telegram_contact", weight=0.1,
                              detail="Moves the conversation to Telegram: " + ", ".join(found["telegram"][:3])))
    score = min(1.0, sum(s.weight for s in signals))
    # Without a brand or a payment / credential ask, wording alone is not enough.
    if brand is None and not any(s.name in ("payment_request_to_upi", "credential_request") for s in signals):
        score = min(score, 0.6)
    return round(score, 3), signals, brand


def message_candidate(text: str, found: dict[str, list[str]], source: SourceType,
                      entities: list[Entity]) -> Candidate:
    digest = hashlib.sha256(" ".join(text.split()).lower().encode("utf-8")).hexdigest()
    score, signals, brand = score_message(text, found)
    channel = "sms" if source == "message" else source
    return Candidate(
        id=uuid.uuid4().hex[:8], kind="message", url=f"message://{digest[:24]}", domain=channel, source=source,
        first_seen=datetime.now(UTC), risk_score=score, verdict=url_features.verdict_for(score),
        brand_matched=brand, signals=signals, entities=entities,
        message=MessageSummary(sha256=digest, excerpt=redact(text), upi_ids=found.get("upi_ids", []),
                               phones=found.get("phones", []), telegram=found.get("telegram", [])),
    )
