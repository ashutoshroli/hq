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


# Which shared-entity types matter to each recipient. Drives the recipient-specific
# context block so each report leads with the infrastructure that party can act on.
RECIPIENT_ENTITY_TYPES: dict[Recipient, tuple[str, ...]] = {
    "registrar": ("registrar", "domain"),
    "hosting": ("ip", "asn", "cert_fingerprint"),
    "bank": ("upi_id", "phone"),
    "npci": ("upi_id", "phone"),
    "cert_in": ("ip", "asn", "domain", "registrar", "upi_id", "phone"),
    "safe_browsing": (),  # URLs are listed from members below, not shared entities
}

# Human-readable label for the recipient-specific context header.
RECIPIENT_CONTEXT_LABEL: dict[Recipient, str] = {
    "registrar": "Registrar / domain context",
    "hosting": "Hosting / network context",
    "bank": "Payment handle context",
    "npci": "UPI handle context",
    "cert_in": "Infrastructure context",
    "safe_browsing": "URLs to blocklist",
}


def _recipient_context(campaign: Campaign, members: list[Candidate], recipient: Recipient) -> list[str]:
    """Recipient-specific context derived from the campaign's shared_entities (plus
    enrichment entities when present). Degrades to a '(none available)' note so the
    report never breaks when the relevant entities are absent."""
    lines = ["", f"{RECIPIENT_CONTEXT_LABEL[recipient]}:"]
    if recipient == "safe_browsing":
        urls = [m.url for m in members]
        lines += [f"  - {u}" for u in urls] or ["  - (none available)"]
        return lines

    wanted = RECIPIENT_ENTITY_TYPES.get(recipient, ())
    relevant = [e for e in campaign.shared_entities if e.type in wanted]
    lines += [f"  - {e.type}: {e.value}" for e in relevant] or ["  - (none available)"]
    return lines


def generate(campaign: Campaign, members: list[Candidate], recipient: Recipient) -> TakedownReport:
    lines = [INTRO[recipient], "", f"Campaign: {campaign.name} ({campaign.size} sites, first seen {campaign.first_seen:%Y-%m-%d})", "",
             "Evidence linking these sites:"]
    lines += [f"  - shared {e.type}: {e.value}" for e in campaign.shared_entities] or ["  - (none recorded)"]
    lines += _recipient_context(campaign, members, recipient)
    lines += ["", "Reported URLs:"]
    for m in members:
        reasons = "; ".join(s.name for s in m.signals[:3]) or "n/a"
        lines.append(f"  - {m.url}  (risk {m.risk_score:.2f}, seen {m.first_seen:%Y-%m-%d %H:%M} UTC; {reasons})")
    lines += ["", "Generated automatically; analyst-reviewed before sending."]
    return TakedownReport(campaign_id=campaign.id, recipient=recipient, generated_at=datetime.now(timezone.utc),
                          subject=f"Phishing takedown request: {campaign.name}", body="\n".join(lines))
