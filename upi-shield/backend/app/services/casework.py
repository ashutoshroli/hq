"""Analyst casework: takedown routing, tracked takedown cases, liveness re-checks,
evidence export (Markdown, JSON, STIX 2.1) and dashboard summaries.

Contacts are only ever taken from authoritative data: RDAP (registrar abuse), RIPEstat
(hosting abuse), the platform abuse channels listed below, and phishing-report
addresses published by the brands themselves (``app.brands``). Where no verified
contact exists the plan says so instead of guessing.
"""
from __future__ import annotations

import io
import json
import logging
import re
import statistics
import uuid
import zipfile
from collections import Counter
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from app import brands
from app.schemas import Campaign, Candidate, Recipient, TakedownCase, TakedownPlan, TakedownPlanItem, TargetCheck
from app.services import evasion, takedown, url_features

logger = logging.getLogger(__name__)

# Abuse channels of hosting / site-builder platforms (as published by each platform).
PLATFORM_ABUSE: dict[str, str] = {
    "pages.dev": "https://abuse.cloudflare.com/", "workers.dev": "https://abuse.cloudflare.com/",
    "trycloudflare.com": "https://abuse.cloudflare.com/",
    "vercel.app": "https://vercel.com/abuse", "netlify.app": "fraud@netlify.com",
    "github.io": "https://support.github.com/contact/report-abuse",
    "azurewebsites.net": "https://msrc.microsoft.com/report/abuse",
    "web.core.windows.net": "https://msrc.microsoft.com/report/abuse",
    "000webhostapp.com": "abuse@hostinger.com", "godaddysites.com": "abuse@godaddy.com",
    "web.app": "https://safebrowsing.google.com/safebrowsing/report_phish/",
    "firebaseapp.com": "https://safebrowsing.google.com/safebrowsing/report_phish/",
    "appspot.com": "https://safebrowsing.google.com/safebrowsing/report_phish/",
    "sites.google.com": "https://safebrowsing.google.com/safebrowsing/report_phish/",
    "blogspot.com": "https://safebrowsing.google.com/safebrowsing/report_phish/",
}

FIXED_CHANNELS: dict[str, list[str]] = {
    "cert_in": ["incident@cert-in.org.in"],
    "safe_browsing": ["https://safebrowsing.google.com/safebrowsing/report_phish/",
                      "https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site"],
    "app_store": ["https://safebrowsing.google.com/safebrowsing/report_badware/"],
    "npci": ["https://www.npci.org.in/register-a-complaint"],
    "cybercrime_portal": ["https://cybercrime.gov.in/", "National cybercrime helpline 1930"],
    "telecom": ["https://sancharsaathi.gov.in/sfc/"],
}


def _channel(contacts: list[str]) -> str:
    if not contacts:
        return "lookup_required"
    if all("@" in c for c in contacts):
        return "email"
    return "web_form" if any(c.startswith("http") for c in contacts) else "phone"


def _active(members: list[Candidate]) -> list[Candidate]:
    return [m for m in members if m.review_status != "false_positive"]


def _is_ip(host: str) -> bool:
    return bool(re.fullmatch(r"[\d.]+|\[?[0-9a-f:]+\]?", host or ""))


def _entities(members: list[Candidate], entity_type: str) -> list[str]:
    return sorted({e.value for m in members for e in m.entities if e.type == entity_type})


def takedown_plan(campaign: Campaign, members: list[Candidate]) -> TakedownPlan:
    """Who to contact, through which channel, about which targets."""
    members = _active(members)
    web = [m for m in members if m.kind == "web"]
    apps = [m for m in members if m.kind == "app"]
    items: list[TakedownPlanItem] = []

    # Registrars: one item per registrar, for registered (non-platform, non-IP) domains.
    by_registrar: dict[str, dict] = {}
    for m in web:
        if _is_ip(m.domain) or evasion.free_hosting_platform(m.domain):
            continue
        infra = m.infrastructure
        name = (infra.registrar if infra else None) or "unknown registrar"
        entry = by_registrar.setdefault(name, {"contacts": set(), "targets": set()})
        if infra and infra.registrar_abuse_email:
            entry["contacts"].add(infra.registrar_abuse_email)
        entry["targets"].add(url_features.registered_domain(m.domain))
    for name, entry in sorted(by_registrar.items()):
        contacts = sorted(entry["contacts"])
        items.append(TakedownPlanItem(
            recipient="registrar", channel=_channel(contacts), contacts=contacts, targets=sorted(entry["targets"]),
            rationale=f"Suspend the domain registrations held at {name}"
                      + ("" if contacts else " (no RDAP abuse contact on record; run enrichment)")))

    # Hosting: platform abuse channels for free hosting; network abuse contacts otherwise.
    by_host: dict[str, dict] = {}
    for m in web:
        platform = evasion.free_hosting_platform(m.domain)
        infra = m.infrastructure
        if platform:
            key, contacts = platform, [PLATFORM_ABUSE[platform]] if platform in PLATFORM_ABUSE else []
        elif infra and infra.asn:
            key, contacts = f"{infra.asn} {infra.as_name or ''}".strip(), list(infra.hosting_abuse_contacts)
        else:
            continue
        entry = by_host.setdefault(key, {"contacts": set(), "targets": set()})
        entry["contacts"].update(contacts)
        entry["targets"].add(m.url)
    for name, entry in sorted(by_host.items()):
        contacts = sorted(entry["contacts"])
        items.append(TakedownPlanItem(
            recipient="hosting", channel=_channel(contacts), contacts=contacts, targets=sorted(entry["targets"]),
            rationale=f"Remove the content hosted on {name}"))

    # The impersonated brands' own fraud teams.
    for key in campaign.brands_targeted:
        brand = brands.BRANDS.get(key)
        if brand is None:
            continue
        contacts = list(brand.abuse_contacts)
        items.append(TakedownPlanItem(
            recipient="bank", channel=_channel(contacts), contacts=contacts,
            targets=[m.url for m in members if m.brand_matched == key],
            rationale=f"Notify {brand.display_name} so it can warn customers and pursue its own takedowns"
                      + ("" if contacts else " (no published phishing-report address verified)")))

    upi = _entities(members, "upi_id")
    if upi:
        items.append(TakedownPlanItem(recipient="npci", channel="web_form", contacts=FIXED_CHANNELS["npci"],
                                      targets=upi, rationale="Freeze the UPI handles collecting victims' payments"))
    phones = _entities(members, "phone")
    if phones:
        items.append(TakedownPlanItem(recipient="telecom", channel="web_form", contacts=FIXED_CHANNELS["telecom"],
                                      targets=phones,
                                      rationale="Report fraud phone numbers via Sanchar Saathi (Chakshu)"))
    if apps:
        items.append(TakedownPlanItem(
            recipient="app_store", channel="web_form", contacts=FIXED_CHANNELS["app_store"],
            targets=[f"{m.app.package} ({m.app.sha256})" for m in apps if m.app],
            rationale="Block the fake apps through Google Play Protect"))
    if web:
        items.append(TakedownPlanItem(recipient="safe_browsing", channel="web_form",
                                      contacts=FIXED_CHANNELS["safe_browsing"], targets=[m.url for m in web],
                                      rationale="Warn browser users while takedowns are pending"))
    items.append(TakedownPlanItem(recipient="cert_in", channel="email", contacts=FIXED_CHANNELS["cert_in"],
                                  targets=[campaign.id], rationale="Report the coordinated campaign to CERT-In"))
    items.append(TakedownPlanItem(recipient="cybercrime_portal", channel="web_form",
                                  contacts=FIXED_CHANNELS["cybercrime_portal"], targets=[campaign.id],
                                  rationale="File with the National Cyber Crime Reporting Portal"))
    return TakedownPlan(campaign_id=campaign.id, generated_at=datetime.now(UTC), items=items)


def targets_for(recipient: Recipient, members: list[Candidate]) -> list[str]:
    members = _active(members)
    if recipient in ("registrar",):
        return sorted({url_features.registered_domain(m.domain) for m in members
                       if m.kind == "web" and not _is_ip(m.domain)})
    if recipient == "npci":
        return _entities(members, "upi_id")
    if recipient == "telecom":
        return _entities(members, "phone")
    if recipient == "app_store":
        return [m.url for m in members if m.kind == "app"]
    return [m.url for m in members]


def create_case(campaign: Campaign, members: list[Candidate], recipient: Recipient,
                contact: str | None = None) -> TakedownCase:
    now = datetime.now(UTC)
    if contact is None:
        plan = takedown_plan(campaign, members)
        contact = next((c for item in plan.items if item.recipient == recipient for c in item.contacts), None)
    return TakedownCase(id="td-" + uuid.uuid4().hex[:10], campaign_id=campaign.id, recipient=recipient,
                        contact=contact, targets=targets_for(recipient, members),
                        report=takedown.generate(campaign, _active(members), recipient),
                        created_at=now, updated_at=now)


def apply_status(case: TakedownCase, status: str, note: str | None) -> TakedownCase:
    now = datetime.now(UTC)
    case.status = status
    case.updated_at = now
    if status == "sent" and case.sent_at is None:
        case.sent_at = now
    if status in ("resolved", "rejected"):
        case.resolved_at = now
    if note:
        case.notes.append(f"{now:%Y-%m-%d %H:%M} UTC [{status}] {note}")
    return case


# --- liveness ---------------------------------------------------------------------------

Prober = Callable[[str], tuple[bool, str]]


def probe_url(url: str) -> tuple[bool, str]:
    """Whether a reported URL still serves content. A domain that no longer resolves,
    refuses connections, or answers 404/410/451 counts as taken down."""
    import httpx

    try:
        resp = httpx.get(url, timeout=10.0, follow_redirects=True, verify=False,
                         headers={"User-Agent": "Mozilla/5.0 (Linux; Android 14) Mobile"})
    except httpx.ConnectError as exc:
        return False, f"connection failed ({exc.__class__.__name__})"
    except httpx.HTTPError as exc:
        return True, f"inconclusive: {exc.__class__.__name__}"
    if resp.status_code in (404, 410, 451):
        return False, f"HTTP {resp.status_code}"
    if "suspended" in resp.text[:5000].lower() and "domain" in resp.text[:5000].lower():
        return False, f"HTTP {resp.status_code}, suspension page"
    return True, f"HTTP {resp.status_code}"


def recheck(case: TakedownCase, prober: Prober | None = None) -> TakedownCase:
    """Re-probe every web target; resolve the case automatically when all are down."""
    prober = prober or probe_url
    urls = [t if "://" in t else f"http://{t}/" for t in case.targets
            if not t.startswith("android://") and ("." in t)]
    now = datetime.now(UTC)
    results = []
    for url in urls:
        try:
            live, detail = prober(url)
        except Exception as exc:  # noqa: BLE001 - a probe failure must not lose the case
            live, detail = True, f"probe error: {exc}"
        results.append(TargetCheck(target=url, checked_at=now, live=live, detail=detail))
    case.checks.extend(results)
    case.updated_at = now
    if results and not any(r.live for r in results) and case.status in ("sent", "acknowledged"):
        apply_status(case, "resolved", "All targets offline on re-check")
    return case


# --- exports ----------------------------------------------------------------------------

def _stix_id(kind: str, value: str) -> str:
    return f"{kind}--{uuid.uuid5(uuid.NAMESPACE_URL, f'upi-shield:{kind}:{value}')}"


def stix_bundle(campaign: Campaign, members: list[Candidate]) -> dict:
    """STIX 2.1 bundle (campaign, indicators, infrastructure, relationships) for sharing
    with CERT-In, ISACs or a threat-intelligence platform."""
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    camp_id = _stix_id("campaign", campaign.id)
    objects: list[dict] = [{
        "type": "campaign", "spec_version": "2.1", "id": camp_id, "created": now, "modified": now,
        "name": campaign.name, "first_seen": campaign.first_seen.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "last_seen": campaign.last_seen.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "description": f"{campaign.size} assets impersonating {', '.join(campaign.brands_targeted) or 'unknown'}",
    }]

    def indicator(value: str, pattern: str, name: str) -> None:
        ind = _stix_id("indicator", pattern)
        objects.append({"type": "indicator", "spec_version": "2.1", "id": ind, "created": now, "modified": now,
                        "name": name, "pattern": pattern, "pattern_type": "stix", "valid_from": now,
                        "indicator_types": ["malicious-activity"]})
        objects.append({"type": "relationship", "spec_version": "2.1", "id": _stix_id("relationship", ind),
                        "created": now, "modified": now, "relationship_type": "indicates",
                        "source_ref": ind, "target_ref": camp_id})

    def esc(value: str) -> str:
        return value.replace("\\", "\\\\").replace("'", "\\'")

    for m in _active(members):
        if m.kind == "app" and m.app:
            indicator(m.app.sha256, f"[file:hashes.'SHA-256' = '{m.app.sha256}']", f"Fake app {m.app.package}")
        else:
            indicator(m.url, f"[url:value = '{esc(m.url)}']", f"Phishing URL {m.domain}")
    for ip in _entities(members, "ip"):
        indicator(ip, f"[ipv4-addr:value = '{ip}']", f"Hosting IP {ip}")
    for upi in _entities(members, "upi_id"):
        indicator(upi, f"[x-upi-handle:value = '{esc(upi)}']", f"Mule UPI handle {upi}")
    return {"type": "bundle", "id": _stix_id("bundle", campaign.id + now), "objects": objects}


def markdown_dossier(campaign: Campaign, members: list[Candidate], plan: TakedownPlan,
                     cases: list[TakedownCase]) -> str:
    members = _active(members)
    lines = [f"# {campaign.name}", "",
             f"- Campaign id: `{campaign.id}`",
             f"- Assets: {campaign.size} ({sum(m.kind == 'web' for m in members)} sites, "
             f"{sum(m.kind == 'app' for m in members)} apps)",
             f"- First seen: {campaign.first_seen:%Y-%m-%d %H:%M} UTC; "
             f"last seen {campaign.last_seen:%Y-%m-%d %H:%M} UTC",
             "", "## Linking evidence", ""]
    lines += [f"- {e.type}: `{e.value}`" for e in campaign.shared_entities] or ["- none"]
    lines += ["", "## Assets", "", "| asset | kind | risk | verdict | review | top signals |",
              "|---|---|---|---|---|---|"]
    for m in sorted(members, key=lambda x: -x.risk_score):
        top = ", ".join(s.name for s in sorted(m.signals, key=lambda s: -s.weight)[:3] if s.weight > 0)
        asset = f"{m.app.label} ({m.app.package})" if m.kind == "app" and m.app else m.url
        lines.append(f"| `{asset}` | {m.kind} | {m.risk_score:.2f} | {m.verdict} | {m.review_status} | {top} |")
    lines += ["", "## Takedown plan", ""]
    for item in plan.items:
        contacts = ", ".join(item.contacts) or "lookup required"
        lines.append(f"- **{item.recipient}** via {item.channel} ({contacts}): {item.rationale}; "
                     f"{len(item.targets)} target(s)")
    lines += ["", "## Takedown cases", ""]
    lines += [f"- `{c.id}` {c.recipient} -> {c.contact or 'n/a'}: **{c.status}**, "
              f"updated {c.updated_at:%Y-%m-%d %H:%M} UTC" for c in cases] or ["- none yet"]
    return "\n".join(lines) + "\n"


def evidence_zip(campaign: Campaign, members: list[Candidate], plan: TakedownPlan, cases: list[TakedownCase],
                 evidence_dir: str) -> bytes:
    """Evidence package: dossier, machine-readable data, STIX bundle, reports and screenshots."""
    import os

    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("README.md", markdown_dossier(campaign, members, plan, cases))
        zf.writestr("campaign.json", json.dumps({
            "campaign": campaign.model_dump(mode="json"),
            "members": [m.model_dump(mode="json") for m in members],
            "plan": plan.model_dump(mode="json"),
            "cases": [c.model_dump(mode="json") for c in cases],
        }, indent=2))
        zf.writestr("stix-bundle.json", json.dumps(stix_bundle(campaign, members), indent=2))
        for item in plan.items:
            report = takedown.generate(campaign, _active(members), item.recipient)
            zf.writestr(f"reports/{item.recipient}.txt", f"To: {', '.join(item.contacts)}\n"
                                                          f"Subject: {report.subject}\n\n{report.body}\n")
        for m in members:
            if m.screenshot_url:
                path = os.path.join(evidence_dir, os.path.basename(m.screenshot_url))
                if os.path.isfile(path):
                    zf.write(path, f"screenshots/{m.id}-{os.path.basename(path)}")
    return out.getvalue()


# --- dashboard --------------------------------------------------------------------------

def summary(cands: list[Candidate], campaigns: list[Campaign], cases: list[TakedownCase], days: int = 14) -> dict:
    now = datetime.now(UTC)
    flagged = [c for c in cands if c.verdict != "benign" and c.review_status != "false_positive"]
    start = (now - timedelta(days=days - 1)).date()
    per_day = Counter(c.first_seen.date() for c in flagged if c.first_seen.date() >= start)
    resolved = [c for c in cases if c.status == "resolved" and c.sent_at and c.resolved_at]
    hours = [(c.resolved_at - c.sent_at).total_seconds() / 3600 for c in resolved]
    return {
        "generated_at": now.isoformat(),
        "totals": {"candidates": len(cands), "flagged": len(flagged), "campaigns": len(campaigns),
                   "apps": sum(c.kind == "app" for c in flagged)},
        "verdicts": dict(Counter(c.verdict for c in cands)),
        "review": dict(Counter(c.review_status for c in cands)),
        "sources": dict(Counter(c.source for c in flagged)),
        "brands": dict(Counter(c.brand_matched for c in flagged if c.brand_matched).most_common()),
        "top_signals": dict(Counter(s.name for c in flagged for s in c.signals if s.weight > 0).most_common(10)),
        "detections_per_day": [{"date": (start + timedelta(days=i)).isoformat(),
                                "count": per_day.get(start + timedelta(days=i), 0)} for i in range(days)],
        "takedowns": {"by_status": dict(Counter(c.status for c in cases)), "open": sum(
            c.status in ("drafted", "sent", "acknowledged") for c in cases),
            "median_hours_to_resolution": round(statistics.median(hours), 1) if hours else None},
        "review_queue": [{"id": c.id, "url": c.url, "risk_score": c.risk_score, "brand": c.brand_matched}
                         for c in sorted((c for c in flagged if c.review_status == "unreviewed"),
                                         key=lambda c: -c.risk_score)[:10]],
    }
