"""Takedown report text per recipient. Extend with WHOIS/hosting contacts and screenshots."""
from datetime import datetime, timezone

from app.schemas import Campaign, Candidate, Recipient, TakedownReport

INTRO = {
    "registrar": "Please suspend the domains listed below, which impersonate a payment brand to defraud users.",
    "hosting": "Please disable hosting for the sites listed below, which are phishing pages for UPI/payment fraud.",
    "bank": "The sites below impersonate your brand. Please initiate takedown and block the linked payment handles.",
    "npci": "Please review and block the UPI handles listed below, which collect payments through fraudulent pages.",
    "cert_in": "Reporting a coordinated phishing campaign impersonating Indian payment brands.",
    "safe_browsing": "Please add the URLs below to the phishing blocklist.",
}


def generate(campaign: Campaign, members: list[Candidate], recipient: Recipient) -> TakedownReport:
    lines = [INTRO[recipient], "", f"Campaign: {campaign.name} ({campaign.size} sites, first seen {campaign.first_seen:%Y-%m-%d})", "",
             "Evidence linking these sites:"]
    lines += [f"  - shared {e.type}: {e.value}" for e in campaign.shared_entities] or ["  - (none recorded)"]
    lines += ["", "Reported URLs:"]
    for m in members:
        reasons = "; ".join(s.name for s in m.signals[:3]) or "n/a"
        lines.append(f"  - {m.url}  (risk {m.risk_score:.2f}, seen {m.first_seen:%Y-%m-%d %H:%M} UTC; {reasons})")
    lines += ["", "Generated automatically; analyst-reviewed before sending."]
    return TakedownReport(campaign_id=campaign.id, recipient=recipient, generated_at=datetime.now(timezone.utc),
                          subject=f"Phishing takedown request: {campaign.name}", body="\n".join(lines))
