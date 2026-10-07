"""Fake / malicious Android app (APK) analysis.

Fake banking and UPI apps are distributed as sideloaded APKs through WhatsApp, SMS and
phishing pages. This module statically analyses an APK (no execution, no emulator) and
produces the same ``Candidate`` record as the web pipeline, so apps share the
dashboard, the campaign graph and takedown reporting with phishing pages.

Evidence collected:
  * Identity      - package name, app label, version, signing-certificate SHA-256.
  * Impersonation - brand keyword or typosquat in the label/package, icon similarity
                    to the genuine app's Play Store icon, and use of an official package
                    name with a signing certificate that is not the brand's.
  * Capabilities  - permissions typical of Indian banking trojans: SMS interception
                    (OTP theft), accessibility abuse, overlays, notification access,
                    call redirection and silent package installation.
  * Infrastructure - URLs, hosts, UPI handles, phone numbers and Telegram bot ids
                    found in DEX strings and assets; these become linking entities, so
                    an app is clustered with the phishing pages it talks to.
"""
from __future__ import annotations

import hashlib
import io
import logging
import re
import struct
import uuid
import zipfile
from dataclasses import dataclass, field
from datetime import UTC, datetime

from app import brands
from app.schemas import AppSummary, Candidate, Entity, Signal, SourceType
from app.services import evasion, extractor, imaging, url_features, visual

logger = logging.getLogger(__name__)

MAX_APK_BYTES = 150 * 1024 * 1024
ICON_MATCH = 0.88

# Hosts embedded by common SDKs and the Android platform; they never identify a campaign.
_PLATFORM_HOSTS = (
    "android.com", "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "google-analytics.com",
    "googlesyndication.com", "doubleclick.net", "firebaseio.com", "firebase.com", "crashlytics.com",
    "facebook.com", "fb.com", "fbcdn.net", "apache.org", "w3.org", "xml.org", "xmlpull.org", "json.org",
    "github.com", "jetbrains.com", "kotlinlang.org", "schemas.microsoft.com", "adobe.com", "mozilla.org",
    "example.com", "localhost", "play.google.com", "youtube.com", "gradle.org", "squareup.com", "okhttp3",
    "appsflyer.com", "branch.io", "adjust.com", "onesignal.com", "sentry.io", "bugsnag.com", "amazonaws.com",
    # Messaging platforms are recorded as telegram handles / bot ids instead.
    "t.me", "telegram.me", "telegram.org", "wa.me", "whatsapp.com", "whatsapp.net",
)
_PLATFORM_REGISTERED = {url_features.registered_domain(h) for h in _PLATFORM_HOSTS}

# Permission -> (signal name, weight, explanation).
RISKY_PERMISSIONS: dict[str, tuple[str, float, str]] = {
    "android.permission.RECEIVE_SMS": ("sms_interception", 0.3, "intercepts incoming SMS (OTP theft)"),
    "android.permission.READ_SMS": ("sms_interception", 0.3, "reads stored SMS (OTP theft)"),
    "android.permission.SEND_SMS": ("sms_sending", 0.15, "sends SMS (spreading, premium fraud, SIM binding)"),
    "android.permission.BIND_ACCESSIBILITY_SERVICE": ("accessibility_abuse", 0.25,
                                                       "can read and control other apps' screens"),
    "android.permission.SYSTEM_ALERT_WINDOW": ("overlay_capability", 0.1, "can draw over other apps (fake login)"),
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE": ("notification_access", 0.15,
                                                               "reads notifications (OTP and alerts)"),
    "android.permission.REQUEST_INSTALL_PACKAGES": ("package_installation", 0.1, "installs further APKs"),
    "android.permission.CALL_PHONE": ("call_control", 0.05, "places calls"),
    "android.permission.CALL_FORWARDING": ("call_control", 0.15, "forwards calls"),
    "android.permission.READ_CALL_LOG": ("call_log_access", 0.05, "reads the call log"),
    "android.permission.READ_CONTACTS": ("contacts_access", 0.05, "reads contacts (spreading)"),
    "android.permission.QUERY_ALL_PACKAGES": ("app_inventory", 0.05, "lists installed banking apps"),
}

_TELEGRAM_BOT = re.compile(r"\b(\d{8,11}):AA[A-Za-z0-9_-]{30,40}\b")
_TELEGRAM_LINK = re.compile(r"(?:t\.me|telegram\.me)/([A-Za-z0-9_]{5,32})", re.I)
_URL = re.compile(r"https?://[A-Za-z0-9.-]+(?::\d+)?(?:/[^\s\"'<>]*)?", re.I)
# A phone number only counts when the string *is* a number, a tel:/WhatsApp link, or
# sits next to contact wording; bare digit runs in DEX files are mostly constants.
_PHONE_STRING = re.compile(r"^\s*(?:tel:|https?://wa\.me/)?(?:\+?91[\s-]?)?[6-9]\d{9}\s*$", re.I)
_PHONE_CONTEXT = re.compile(r"\b(call|whatsapp|contact|helpline|customer care|sms to|number)\b", re.I)
_TEXT_ASSET = re.compile(r"\.(json|txt|xml|html?|js|properties|cfg|conf)$", re.I)


class ApkError(ValueError):
    """The upload is not a parseable APK."""


@dataclass
class AppInfo:
    sha256: str
    package: str
    label: str
    version: str | None = None
    permissions: list[str] = field(default_factory=list)
    cert_sha256: list[str] = field(default_factory=list)
    icon: bytes | None = field(default=None, repr=False)
    strings: list[str] = field(default_factory=list, repr=False)
    has_launcher: bool = True


# --- DEX string table ---------------------------------------------------------------------

def _uleb128(data: bytes, offset: int) -> tuple[int, int]:
    result = shift = 0
    while True:
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if byte < 0x80:
            return result, offset
        shift += 7


def dex_strings(dex: bytes, limit: int = 200_000) -> list[str]:
    """Return the string constants of a DEX file (string_ids table, MUTF-8 decoded)."""
    if len(dex) < 0x70 or not dex.startswith(b"dex\n"):
        return []
    count, table = struct.unpack_from("<II", dex, 0x38)
    out: list[str] = []
    for i in range(min(count, limit)):
        try:
            (data_off,) = struct.unpack_from("<I", dex, table + 4 * i)
            _length, start = _uleb128(dex, data_off)
            end = dex.index(b"\x00", start)
            out.append(dex[start:end].decode("utf-8", errors="replace"))
        except (struct.error, ValueError, IndexError):
            break
    return out


# --- APK parsing --------------------------------------------------------------------------

def _icon_bytes(apk, zf: zipfile.ZipFile) -> bytes | None:
    """Best raster icon. Adaptive icons are XML; fall back to the largest bitmap that
    shares the icon's resource name (or any launcher-like bitmap)."""
    path = None
    try:
        path = apk.get_app_icon()
    except Exception:  # noqa: BLE001
        path = None
    names = zf.namelist()
    if path and not path.endswith(".xml") and path in names:
        return zf.read(path)
    stem = (path or "ic_launcher").rsplit("/", 1)[-1].rsplit(".", 1)[0]
    bitmaps = [n for n in names if n.startswith("res/") and n.lower().endswith((".png", ".webp"))
               and stem in n.rsplit("/", 1)[-1]]
    if not bitmaps:
        bitmaps = [n for n in names if n.startswith("res/") and "launcher" in n.lower()
                   and n.lower().endswith((".png", ".webp"))]
    if not bitmaps:
        return None
    return zf.read(max(bitmaps, key=lambda n: zf.getinfo(n).file_size))


def parse_apk(data: bytes) -> AppInfo:
    """Statically parse an APK into an ``AppInfo``. Raises ``ApkError`` for invalid input."""
    if not data or len(data) > MAX_APK_BYTES:
        raise ApkError("APK is empty or exceeds the size limit")
    if not zipfile.is_zipfile(io.BytesIO(data)):
        raise ApkError("upload is not a ZIP/APK archive")
    try:
        logging.getLogger("pyaxmlparser").setLevel(logging.ERROR)
        from pyaxmlparser import APK

        apk = APK(data, raw=True)
        if not apk.is_valid_APK():
            raise ApkError("archive has no valid AndroidManifest.xml")
    except ApkError:
        raise
    except Exception as exc:  # noqa: BLE001 - malformed manifests are common in malware
        raise ApkError(f"cannot parse AndroidManifest.xml: {exc}") from exc

    zf = zipfile.ZipFile(io.BytesIO(data))
    certs: list[bytes] = []
    for getter in ("get_certificates_der_v3", "get_certificates_der_v2"):
        try:
            certs = list(getattr(apk, getter)() or [])
        except Exception:  # noqa: BLE001
            certs = []
        if certs:
            break
    if not certs:
        try:
            certs = [apk.get_certificate_der(n) for n in apk.get_signature_names()]
        except Exception:  # noqa: BLE001 - unsigned or malformed signature
            certs = []

    strings: list[str] = []
    for name in zf.namelist():
        if re.fullmatch(r"classes\d*\.dex", name):
            strings.extend(dex_strings(zf.read(name)))
        elif name.startswith("assets/") and _TEXT_ASSET.search(name) and zf.getinfo(name).file_size < 2_000_000:
            strings.extend(zf.read(name).decode("utf-8", errors="ignore").splitlines())

    try:
        label = apk.get_app_name() or apk.package
    except Exception:  # noqa: BLE001
        label = apk.package
    try:
        has_launcher = bool(apk.get_main_activity())
    except Exception:  # noqa: BLE001
        has_launcher = True
    return AppInfo(
        sha256=hashlib.sha256(data).hexdigest(), package=apk.package or "unknown", label=str(label),
        version=apk.version_name, permissions=sorted(set(apk.get_permissions() or [])),
        cert_sha256=[hashlib.sha256(c).hexdigest() for c in certs if c], icon=_icon_bytes(apk, zf),
        strings=strings, has_launcher=has_launcher,
    )


# --- indicators ---------------------------------------------------------------------------

def _is_platform_host(host: str) -> bool:
    return url_features.registered_domain(host) in _PLATFORM_REGISTERED or "." not in host


def extract_indicators(strings: list[str]) -> dict[str, list[str]]:
    """Network and payment indicators embedded in the app."""
    blob = "\n".join(s for s in strings if 4 <= len(s) <= 4000)
    hosts: list[str] = []
    for url in _URL.findall(blob):
        host = url_features.host_of(url)
        if host and not _is_platform_host(host) and brands.official_brand_for(url_features.registered_domain(host)) \
                is None:
            hosts.append(host)
    bots = list(dict.fromkeys(_TELEGRAM_BOT.findall(blob)))
    # Bot tokens start with a 10-digit id that would otherwise parse as a phone number.
    found = extractor.extract(_TELEGRAM_BOT.sub(" ", blob))
    phone_text = "\n".join(s for s in strings if _PHONE_STRING.match(s) or (len(s) < 300 and _PHONE_CONTEXT.search(s)))
    found["phones"] = extractor.extract(phone_text)["phones"]
    return {
        "hosts": list(dict.fromkeys(hosts))[:50],
        "upi_ids": [u for u in found["upi_ids"] if "." not in u.split("@")[-1]][:20],
        "phones": found["phones"][:20],
        "telegram_bots": bots[:10],
        "telegram": list(dict.fromkeys(m.lower() for m in _TELEGRAM_LINK.findall(blob)))[:10],
    }


# --- scoring ------------------------------------------------------------------------------

def _official_packages() -> dict[str, str]:
    return {pkg: b.key for b in brands.BRANDS.values() for pkg in b.android_packages}


def _known_certs(brand_key: str) -> set[str]:
    refs = visual.brand_references().get(brand_key, {})
    return {c for app in refs.get("apps", []) for c in app.get("cert_sha256", [])}


def icon_brand_match(icon: bytes | None) -> tuple[str | None, float]:
    """Best match of an app icon against genuine brand app icons (Play Store)."""
    if not icon:
        return None, 0.0
    ph, dh = imaging.phash(icon), imaging.dhash(icon)
    best: tuple[str | None, float] = (None, 0.0)
    for key, entry in visual.brand_references().items():
        for app in entry.get("apps", []):
            sim = (imaging.hash_similarity(ph, app.get("icon_phash"))
                   + imaging.hash_similarity(dh, app.get("icon_dhash"))) / 2
            if sim > best[1]:
                best = (key, sim)
    return best


def _text_brand(text: str) -> tuple[str | None, str | None]:
    """Brand named (or typosquatted) in an app label / package name."""
    skeleton = evasion.skeleton(text)
    flat = re.sub(r"[^a-z0-9]", "", skeleton)
    index = brands.keyword_index()
    for kw, key in index.items():
        if len(kw) >= 3 and kw in flat:
            return key, "name"
    squat = evasion.typosquat_keyword(skeleton, list(index))
    return (index[squat], "typosquat") if squat else (None, None)


def score_app(info: AppInfo) -> tuple[float, list[Signal], str | None]:
    signals: list[Signal] = []
    official = _official_packages()
    brand: str | None = official.get(info.package)

    if brand is not None:
        known = _known_certs(brand)
        if known and not set(info.cert_sha256) & known:
            signals.append(Signal(name="repackaged_official_app", weight=0.7,
                                  detail=f"Uses the official {brand} package name {info.package} but is signed "
                                         "with a different certificate"))
        else:
            signals.append(Signal(name="official_package_name", weight=0.0,
                                  detail=f"{info.package} is the official {brand} package"
                                         + ("" if known else "; signing certificate not verified")))
    else:
        for text, what in ((info.label, "label"), (info.package, "package name")):
            hit, how = _text_brand(text)
            if hit:
                brand = brand or hit
                signals.append(Signal(name="brand_impersonating_app", weight=0.45,
                                      detail=f"App {what} '{text}' "
                                             + ("names" if how == "name" else "typosquats") + f" {hit}, "
                                             f"but {info.package} is not an official {hit} app"))
                break
        icon_brand, sim = icon_brand_match(info.icon)
        if icon_brand and sim >= ICON_MATCH:
            brand = brand or icon_brand
            signals.append(Signal(name="app_icon_impersonation", weight=0.4,
                                  detail=f"App icon is {sim:.0%} similar to the genuine {icon_brand} app icon"))

    granted = set(info.permissions)
    seen: set[str] = set()
    for perm, (name, weight, why) in RISKY_PERMISSIONS.items():
        if perm in granted and name not in seen:
            seen.add(name)
            signals.append(Signal(name=name, weight=weight, detail=f"Requests {perm.rsplit('.', 1)[-1]}: {why}"))
    if {"sms_interception", "accessibility_abuse"} <= seen or {"sms_interception", "notification_access"} <= seen:
        signals.append(Signal(name="banking_trojan_profile", weight=0.2,
                              detail="Combines OTP interception with screen or notification access"))
    if not info.has_launcher:
        signals.append(Signal(name="hidden_launcher_icon", weight=0.1, detail="No launcher activity (hides itself)"))
    if not info.cert_sha256:
        signals.append(Signal(name="unsigned_apk", weight=0.1, detail="APK has no readable signing certificate"))

    indicators = extract_indicators(info.strings)
    if indicators["telegram_bots"]:
        signals.append(Signal(name="telegram_bot_exfiltration", weight=0.25,
                              detail=f"Embeds Telegram bot token(s) for bot id(s) "
                                     f"{', '.join(indicators['telegram_bots'][:3])}"))
    if indicators["upi_ids"]:
        signals.append(Signal(name="embedded_upi_handles", weight=0.1,
                              detail="Embeds UPI handle(s): " + ", ".join(indicators["upi_ids"][:3])))

    # Malicious capabilities without any impersonation still deserve review, but
    # capabilities alone (many legitimate apps read SMS) are capped below "malicious".
    score = sum(s.weight for s in signals)
    if brand is None or any(s.name == "official_package_name" for s in signals):
        score = min(score, 0.6)
    return round(min(1.0, score), 3), signals, brand


def app_entities(info: AppInfo, distribution_host: str | None = None) -> list[Entity]:
    indicators = extract_indicators(info.strings)
    entities = [Entity(type="package_name", value=info.package), Entity(type="apk_sha256", value=info.sha256)]
    entities += [Entity(type="signing_cert", value=c) for c in info.cert_sha256]
    if info.icon:
        entities.append(Entity(type="favicon_hash", value=hashlib.md5(info.icon).hexdigest()[:16]))
    entities += [Entity(type="domain", value=h) for h in indicators["hosts"]]
    entities += [Entity(type="upi_id", value=u) for u in indicators["upi_ids"]]
    entities += [Entity(type="phone", value=p) for p in indicators["phones"]]
    entities += [Entity(type="telegram", value=f"bot:{b}") for b in indicators["telegram_bots"]]
    entities += [Entity(type="telegram", value=t) for t in indicators["telegram"]]
    if distribution_host:
        entities.append(Entity(type="domain", value=distribution_host))
    seen: set[tuple[str, str]] = set()
    return [e for e in entities if not ((e.type, e.value) in seen or seen.add((e.type, e.value)))]


def analyze_apk(data: bytes, source: SourceType = "user_report", origin_url: str | None = None,
                extra_entities: list[Entity] | None = None) -> Candidate:
    """Analyse APK bytes and return a Candidate (``kind="app"``)."""
    info = parse_apk(data)
    score, signals, brand = score_app(info)
    host = url_features.host_of(origin_url) if origin_url else None
    if origin_url:
        signals.append(Signal(name="sideloaded_distribution", weight=0.0,
                              detail=f"Distributed outside Google Play from {origin_url}"))
    entities = app_entities(info, host) + list(extra_entities or [])
    icon_sim = icon_brand_match(info.icon)[1] if brand else None
    return Candidate(
        id=uuid.uuid4().hex[:8], kind="app", url=f"android://{info.package}?sha256={info.sha256[:16]}",
        domain=info.package, source=source, first_seen=datetime.now(UTC), risk_score=score,
        verdict=url_features.verdict_for(score), brand_matched=brand,
        visual_similarity=round(icon_sim, 3) if icon_sim else None, signals=signals, entities=entities,
        app=AppSummary(package=info.package, label=info.label, version=info.version, sha256=info.sha256,
                       permissions=info.permissions, cert_sha256=info.cert_sha256, origin_url=origin_url),
    )
