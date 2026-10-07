"""Takedown report text per recipient (registrar, hosting, brand, NPCI, CERT-In, browsers,
app stores, the national cybercrime portal and telecom regulators)."""
import re
from datetime import UTC, datetime

from app.schemas import Campaign, Candidate, Recipient, TakedownReport

INTRO = {
    "registrar": "Please suspend the domains listed below, which impersonate a payment brand to defraud users.",
    "hosting": "Please disable hosting for the sites listed below, which are phishing pages for UPI/payment fraud.",
    "bank": "The sites below impersonate your brand. Please initiate takedown and block the linked payment handles.",
    "npci": "Please review and block the UPI handles listed below, which collect payments through fraudulent pages.",
    "cert_in": "Reporting a coordinated phishing campaign impersonating Indian payment brands.",
    "safe_browsing": "Please add the URLs below to the phishing blocklist.",
    "app_store": ("Please remove the Android applications below and flag them in Google Play Protect. "
                  "They impersonate payment brands to steal UPI credentials and OTPs."),
    "cybercrime_portal": ("Complaint regarding an organised online financial fraud campaign that impersonates "
                          "Indian payment brands through the websites, apps and payment handles listed below."),
    "telecom": ("The phone numbers below are advertised on fraudulent payment pages as contact numbers. "
                "Please investigate and disconnect them."),
}


# Which shared-entity types matter to each recipient. Drives the recipient-specific
# context block so each report leads with the infrastructure that party can act on.
RECIPIENT_ENTITY_TYPES: dict[Recipient, tuple[str, ...]] = {
    "registrar": ("registrar",),
    "hosting": ("ip", "asn", "cert_fingerprint"),
    "bank": ("upi_id", "phone"),
    "npci": ("upi_id", "phone"),
    "cert_in": ("ip", "asn", "registrar", "upi_id", "phone"),
    "safe_browsing": (),  # URLs are listed from members below, not shared entities
    "app_store": ("signing_cert", "package_name", "domain"),
    "cybercrime_portal": ("upi_id", "phone", "telegram", "ip"),
    "telecom": ("phone",),
}

# Recipients who need the concrete domains being taken down. 'domain' is unique per
# candidate (never a shared entity), so it is read from members (like safe_browsing
# reads URLs) rather than from campaign.shared_entities.
RECIPIENT_WANTS_DOMAINS: frozenset[Recipient] = frozenset({"registrar", "cert_in", "cybercrime_portal"})

# Human-readable label for the recipient-specific context header.
RECIPIENT_CONTEXT_LABEL: dict[Recipient, str] = {
    "registrar": "Registrar / domain context",
    "hosting": "Hosting / network context",
    "bank": "Payment handle context",
    "npci": "UPI handle context",
    "cert_in": "Infrastructure context",
    "safe_browsing": "URLs to blocklist",
    "app_store": "Application context",
    "cybercrime_portal": "Payment and contact identifiers",
    "telecom": "Fraud phone numbers",
}


def _recipient_context(campaign: Campaign, members: list[Candidate], recipient: Recipient) -> list[str]:
    """Recipient-specific context derived from the campaign's shared_entities (plus
    enrichment entities when present). Degrades to a '(none available)' note so the
    report never breaks when the relevant entities are absent."""
    lines = ["", f"{RECIPIENT_CONTEXT_LABEL[recipient]}:"]
    if recipient == "safe_browsing":
        urls = [m.url for m in members if m.kind == "web"]
        lines += [f"  - {u}" for u in urls] or ["  - (none available)"]
        return lines
    if recipient == "app_store":
        for m in (m for m in members if m.kind == "app" and m.app):
            lines.append(f"  - {m.app.label} ({m.app.package}, version {m.app.version or 'unknown'})")
            lines.append(f"      APK SHA-256: {m.app.sha256}")
            for cert in m.app.cert_sha256:
                lines.append(f"      signing certificate SHA-256: {cert}")
            if m.app.origin_url:
                lines.append(f"      distributed from: {m.app.origin_url}")
        if len(lines) == 2:
            lines.append("  - (no Android applications in this campaign)")

    context: list[str] = []
    # Per-member domains for recipients that act on the domains directly (registrar,
    # cert_in). 'domain' is unique per candidate, so pull it from members, not shared.
    if recipient in RECIPIENT_WANTS_DOMAINS:
        seen: set[str] = set()
        for m in members:
            # Registrars act on registered names only: skip apps and raw-IP hosts.
            if m.kind == "app" or re.fullmatch(r"[\d.]+|\[?[0-9a-f:]+\]?", m.domain or ""):
                continue
            if m.domain and m.domain not in seen:
                seen.add(m.domain)
                context.append(f"  - domain: {m.domain}")

    wanted = RECIPIENT_ENTITY_TYPES.get(recipient, ())
    relevant = [e for e in campaign.shared_entities if e.type in wanted]
    context += [f"  - {e.type}: {e.value}" for e in relevant]

    lines += context or ["  - (none available)"]
    return lines


def generate(campaign: Campaign, members: list[Candidate], recipient: Recipient) -> TakedownReport:
    header = f"Campaign: {campaign.name} ({campaign.size} sites, first seen {campaign.first_seen:%Y-%m-%d})"
    lines = [INTRO[recipient], "", header, "", "Evidence linking these sites:"]
    lines += [f"  - shared {e.type}: {e.value}" for e in campaign.shared_entities] or ["  - (none recorded)"]
    lines += _recipient_context(campaign, members, recipient)
    lines += ["", "Reported URLs:"]
    for m in members:
        reasons = "; ".join(s.name for s in m.signals if s.weight > 0)[:200] or "n/a"
        what = f"Android app {m.app.label} ({m.app.package})" if m.kind == "app" and m.app else m.url
        lines.append(f"  - {what}  (risk {m.risk_score:.2f}, seen {m.first_seen:%Y-%m-%d %H:%M} UTC; {reasons})")
        if m.screenshot_url:
            lines.append(f"      screenshot evidence: {m.screenshot_url}")
    lines += ["", "Generated automatically; analyst-reviewed before sending."]
    return TakedownReport(campaign_id=campaign.id, recipient=recipient, generated_at=datetime.now(UTC),
                          subject=f"Phishing takedown request: {campaign.name}", body="\n".join(lines))
