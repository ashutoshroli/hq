"""Behavioural analysis of a fetched page: flags phishing tells from the parsed DOM.

Pure-python, offline and deterministic. Consumes a fetcher.FetchResult and returns a
list of Signal rows (name, weight, detail). Returns [] when there is no html to inspect.

Tells detected:
  * credential input fields  : UPI PIN / OTP / CVV / card / password inputs (by name/
                               type/placeholder heuristics on the parsed forms)
  * cross-domain form action : a <form action> posting to a different host than the page
  * obfuscated / eval'd JS    : eval( / atob( / document.write / unescape / escape and
                               long base64 blobs in inline scripts
  * credential-harvesting words : lure/credential phrases in the visible text
"""
import logging
import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

from app.schemas import Signal

logger = logging.getLogger(__name__)

# Sensitive input heuristics: substring -> human label.
_SENSITIVE_FIELDS: dict[str, str] = {
    "upi_pin": "UPI PIN",
    "upipin": "UPI PIN",
    "mpin": "UPI/M-PIN",
    "upi-pin": "UPI PIN",
    "otp": "OTP",
    "one_time": "OTP",
    "onetime": "OTP",
    "cvv": "card CVV",
    "card": "card number",
    "cardnumber": "card number",
    "cardno": "card number",
    "expiry": "card expiry",
    "password": "password",
    "passwd": "password",
    "pwd": "password",
    "pin": "PIN",
    "atm": "ATM/debit details",
}

# JS obfuscation / dynamic-exec heuristics.
_OBFUSCATION_PATTERNS = [
    (re.compile(r"\beval\s*\("), "eval("),
    (re.compile(r"\batob\s*\("), "atob("),
    (re.compile(r"\bunescape\s*\("), "unescape("),
    (re.compile(r"\bescape\s*\("), "escape("),
    (re.compile(r"document\.write\s*\("), "document.write("),
    (re.compile(r"String\.fromCharCode\s*\("), "String.fromCharCode("),
    (re.compile(r"\bFunction\s*\(\s*['\"]"), "Function(\"...\")"),
]
# Long base64-ish blob (common in packed/obfuscated payloads).
_BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{120,}={0,2}")

# Imperative credential prompts. Bare product words ("credit card", "debit card")
# are deliberately excluded: every genuine bank and wallet page mentions them.
_HARVEST_WORDS = (
    "enter your upi pin", "enter upi pin", "enter otp", "verify otp", "enter your otp",
    "enter card number", "enter your card number", "enter cvv", "enter your cvv",
    "net banking password", "enter your password", "atm pin", "enter your aadhaar",
    "update your kyc", "complete your kyc", "complete kyc", "verify your account",
    "account will be blocked", "account has been blocked", "account will be suspended",
)


class _ScriptCollector(HTMLParser):
    """Collects inline <script> text, <input placeholder> values, and visible text."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.inline_scripts: list[str] = []
        self.placeholders: list[str] = []
        self.text_parts: list[str] = []
        self._in_script = False
        self._in_style = False

    def handle_starttag(self, tag, attrs):
        if tag == "script":
            # Only inline scripts (no src) carry obfuscated payloads worth scanning.
            if not dict((k.lower(), v) for k, v in attrs).get("src"):
                self._in_script = True
        elif tag == "style":
            self._in_style = True
        elif tag == "input":
            a = {k.lower(): (v or "") for k, v in attrs}
            if a.get("placeholder"):
                self.placeholders.append(a["placeholder"])

    def handle_endtag(self, tag):
        if tag == "script":
            self._in_script = False
        elif tag == "style":
            self._in_style = False

    def handle_data(self, data):
        if self._in_script:
            self.inline_scripts.append(data)
        elif not self._in_style:
            self.text_parts.append(data)

    @property
    def text(self) -> str:
        return " ".join(" ".join(self.text_parts).split())


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:  # noqa: BLE001
        return ""


def analyze_behaviour(fetch_result, impersonating: bool = True) -> list[Signal]:
    """Inspect a fetched page and return phishing-behaviour Signals ([] when no html).

    Obfuscated JavaScript and credential prompts are common on legitimate sites too
    (minified bundles, login pages). They carry full weight only in a phishing context:
    the page collects sensitive credentials, or it impersonates a brand
    (``impersonating``). Otherwise they are reported with a reduced weight.
    """
    if fetch_result is None:
        return []
    html = getattr(fetch_result, "html", "") or ""
    if not html:
        return []

    signals: list[Signal] = []

    page_url = getattr(fetch_result, "final_url", "") or getattr(fetch_result, "url", "") or ""
    page_host = _host(page_url)
    forms = getattr(fetch_result, "forms", None) or []

    # --- 1) Sensitive credential input fields (from parsed forms) ---
    found_fields: dict[str, str] = {}
    for form in forms:
        for inp in form.get("inputs", []) or []:
            name = (inp.get("name", "") or "").lower()
            itype = (inp.get("type", "") or "").lower()
            haystack = f"{name} {itype}"
            for key, label in _SENSITIVE_FIELDS.items():
                if key in haystack:
                    found_fields.setdefault(key, label)
            if itype == "password":
                found_fields.setdefault("password", "password")

    # --- parse scripts / placeholders / visible text ---
    collector = _ScriptCollector()
    try:
        collector.feed(html)
    except Exception as exc:  # noqa: BLE001
        logger.warning("behaviour: HTML parse error: %s", exc)

    for ph in collector.placeholders:
        low = ph.lower()
        for key, label in _SENSITIVE_FIELDS.items():
            if key.replace("_", " ") in low or key in low:
                found_fields.setdefault(key, label)

    if found_fields:
        labels = sorted(set(found_fields.values()))
        weight = 0.4 if any(k in found_fields for k in ("upi_pin", "upipin", "mpin", "otp", "cvv")) else 0.25
        signals.append(Signal(name="credential_input_fields", weight=weight,
                              detail="Collects sensitive credentials: " + ", ".join(labels)))

    # --- 2) Cross-domain form action ---
    if page_host:
        for form in forms:
            action = (form.get("action", "") or "").strip()
            if not action:
                continue
            action_host = _host(urljoin(page_url, action))
            if action_host and action_host != page_host:
                signals.append(Signal(name="cross_domain_form_action", weight=0.3,
                                      detail=(f"Form submits to a different host "
                                              f"({action_host}) than the page ({page_host})")))
                break

    # --- 3) Obfuscated / dynamically-executed inline JS ---
    script_blob = "\n".join(collector.inline_scripts)
    hits: list[str] = []
    for pattern, label in _OBFUSCATION_PATTERNS:
        if pattern.search(script_blob):
            hits.append(label)
    if _BASE64_BLOB.search(script_blob):
        hits.append("long base64 blob")
    in_context = impersonating or bool(found_fields)
    if hits:
        signals.append(Signal(name="obfuscated_js", weight=0.25 if in_context else 0.05,
                              detail="Obfuscated/eval'd inline JS: " + ", ".join(sorted(set(hits)))))

    # --- 4) Credential-harvesting keywords in visible text ---
    low_text = collector.text.lower()
    harvest_hits = [w for w in _HARVEST_WORDS if w in low_text]
    if harvest_hits:
        signals.append(Signal(name="credential_harvesting_text", weight=0.2 if in_context else 0.1,
                              detail="Credential-harvesting prompts: " + ", ".join(harvest_hits[:5])))

    return signals
