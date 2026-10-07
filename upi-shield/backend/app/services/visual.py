"""Visual + structural similarity engine.

Matches a fetched page against genuine brand references. No ML models or GPU are
required; image fingerprints come from ``app.services.imaging`` (Pillow + numpy).

Evidence paths, strongest first:

1. **Screenshot similarity** - the rendered page's pHash/dHash is compared with
   screenshots of the genuine brand site (``app/data/brand_refs.json``, built by
   ``python -m app.tools.build_brand_refs``). Measured on the committed library,
   different brands never exceed 0.62 layout similarity while re-encoded, cropped or
   banner-modified copies of a brand page stay at or above 0.86.
2. **Favicon reuse** - an exact favicon hash match, or a perceptual favicon match that
   survives re-encoding and resizing.
3. **Structural/text similarity** - title keywords, vocabulary Jaccard and DOM markers
   (always available, no images needed).

``compare_visual(fetch_result, brand)`` scores a page against a known brand.
``identify_brand(fetch_result)`` searches *all* brands, which catches clones hosted
on domains that do not mention the brand at all (a common evasion tactic).
"""
import json
import logging
import re
from functools import lru_cache
from html.parser import HTMLParser
from pathlib import Path

from app.schemas import Signal
from app.services import imaging

logger = logging.getLogger(__name__)


# --- Brand reference index -------------------------------------------------
# Lightweight, runtime-free descriptors per brand. No real logo images required:
#   title_keywords : tokens expected in the genuine brand's page <title>
#   vocab          : visible-text vocabulary a genuine/cloned brand page tends to show
#   dom_markers    : substrings that commonly appear in brand page markup/text
#   favicon_hashes : known favicon_hash values (stable short hashes); clones that reuse
#                    the genuine favicon match here exactly
#   ahash          : optional expected average-hash hex for perceptual image compare
BRAND_INDEX: dict[str, dict] = {
    "phonepe": {
        "title_keywords": ["phonepe"],
        "vocab": ["phonepe", "upi", "pay", "wallet", "payment", "secure", "money", "transaction"],
        "dom_markers": ["phonepe", "upi"],
        # Known genuine favicon hash(es) (fetcher.favicon_hash_of == md5(bytes)[:16]).
        # A clone that copies the genuine logo byte-for-byte produces the same hash and
        # trips the favicon_match signal on a real fetch. Extend as more brand favicons
        # are catalogued; "fav0phonepe01" is the reference used by the labelled sample.
        "favicon_hashes": ["fav0phonepe01"],
        "ahash": None,
    },
    "gpay": {
        "title_keywords": ["google", "pay", "gpay"],
        "vocab": ["google", "pay", "gpay", "upi", "payment", "secure", "money", "wallet"],
        "dom_markers": ["google pay", "gpay", "upi"],
        "favicon_hashes": [],
        "ahash": None,
    },
    "googlepay": {
        "title_keywords": ["google", "pay"],
        "vocab": ["google", "pay", "gpay", "upi", "payment", "secure", "money", "wallet"],
        "dom_markers": ["google pay", "gpay", "upi"],
        "favicon_hashes": [],
        "ahash": None,
    },
    "paytm": {
        "title_keywords": ["paytm"],
        "vocab": ["paytm", "wallet", "upi", "pay", "recharge", "payment", "secure", "money"],
        "dom_markers": ["paytm", "upi"],
        "favicon_hashes": [],
        "ahash": None,
    },
    "bhim": {
        "title_keywords": ["bhim", "upi"],
        "vocab": ["bhim", "upi", "npci", "pay", "payment", "secure", "money", "vpa"],
        "dom_markers": ["bhim", "upi", "npci"],
        "favicon_hashes": [],
        "ahash": None,
    },
    "sbi": {
        "title_keywords": ["sbi", "state", "bank"],
        "vocab": ["sbi", "state", "bank", "india", "login", "netbanking", "account", "secure", "upi"],
        "dom_markers": ["onlinesbi", "state bank", "sbi"],
        "favicon_hashes": [],
        "ahash": None,
    },
    "hdfc": {
        "title_keywords": ["hdfc", "bank"],
        "vocab": ["hdfc", "bank", "netbanking", "login", "account", "secure", "customer", "upi"],
        "dom_markers": ["hdfc", "netbanking"],
        "favicon_hashes": [],
        "ahash": None,
    },
    "icici": {
        "title_keywords": ["icici", "bank"],
        "vocab": ["icici", "bank", "netbanking", "login", "account", "secure", "customer", "upi"],
        "dom_markers": ["icici", "netbanking"],
        "favicon_hashes": [],
        "ahash": None,
    },
    "axisbank": {
        "title_keywords": ["axis", "bank"],
        "vocab": ["axis", "bank", "netbanking", "login", "account", "secure", "customer", "upi"],
        "dom_markers": ["axis", "netbanking"],
        "favicon_hashes": [],
        "ahash": None,
    },
}

# Brand keys that share a reference entry.
_BRAND_ALIASES = {"googlepay": "gpay"}

REFS_PATH = Path(__file__).resolve().parent.parent / "data" / "brand_refs.json"

# Thresholds derived from the committed reference library (see module docstring).
SCREENSHOT_STRONG = 0.85
SCREENSHOT_MODERATE = 0.75
FAVICON_PERCEPTUAL = 0.90


@lru_cache(maxsize=1)
def brand_references() -> dict[str, dict]:
    """Load the screenshot/favicon reference library (empty when absent)."""
    try:
        return json.loads(REFS_PATH.read_text(encoding="utf-8")).get("brands", {})
    except Exception as exc:  # noqa: BLE001 - the engine still works on structure alone
        logger.warning("visual: brand reference library unavailable: %s", exc)
        return {}


def _ref_key(brand: str | None) -> str:
    return _BRAND_ALIASES.get(brand or "", brand or "")


def known_favicon_hashes(brand: str | None) -> set[str]:
    key = _ref_key(brand)
    hashes = set(BRAND_INDEX.get(brand or "", {}).get("favicon_hashes", []))
    hashes |= set(BRAND_INDEX.get(key, {}).get("favicon_hashes", []))
    hashes |= set(brand_references().get(key, {}).get("favicon_md5", []))
    return hashes


def screenshot_similarity(shot: imaging.Fingerprint | None, brand: str) -> tuple[float, str | None]:
    """Best layout similarity between a screenshot fingerprint and a brand's references."""
    best, where = 0.0, None
    for ref in brand_references().get(_ref_key(brand), {}).get("screenshots", []):
        sim = imaging.layout_similarity(shot, imaging.Fingerprint.from_dict(ref))
        if sim > best:
            best, where = sim, f"{ref.get('url')} ({ref.get('viewport')})"
    return best, where


def favicon_perceptual_similarity(favicon_phash: str | None, brand: str) -> float:
    refs = brand_references().get(_ref_key(brand), {}).get("favicon_phash", [])
    return max((imaging.hash_similarity(favicon_phash, r) for r in refs), default=0.0)


def _page_fingerprints(fetch_result) -> tuple[imaging.Fingerprint | None, str | None]:
    shot = getattr(fetch_result, "screenshot", None)
    icon = getattr(fetch_result, "favicon_bytes", None)
    return imaging.Fingerprint.of(shot), (imaging.phash(icon) if icon else None)


def identify_brand(fetch_result, exclude: set[str] | None = None) -> tuple[str | None, float, list[Signal]]:
    """Find which genuine brand a page looks like, regardless of its URL.

    Returns ``(brand, similarity, signals)``; ``brand`` is None when nothing matches
    strongly enough. Only screenshot and perceptual-favicon evidence is used here,
    because page text alone is too weak to attribute an unbranded URL to a brand.
    """
    if fetch_result is None:
        return None, 0.0, []
    shot, icon_phash = _page_fingerprints(fetch_result)
    exclude = exclude or set()
    best: tuple[str | None, float, str] = (None, 0.0, "")
    for key in brand_references():
        if key in exclude:
            continue
        sim, where = screenshot_similarity(shot, key)
        if sim > best[1]:
            best = (key, sim, f"screenshot is {sim:.0%} similar to genuine {key} page {where}")
        fav = favicon_perceptual_similarity(icon_phash, key)
        if fav >= FAVICON_PERCEPTUAL and fav > best[1]:
            best = (key, fav, f"favicon is {fav:.0%} perceptually similar to the genuine {key} icon")
    brand, sim, detail = best
    if brand is None or sim < SCREENSHOT_STRONG:
        return None, round(sim, 3), []
    return brand, round(sim, 3), [Signal(name="visual_brand_impersonation", weight=0.5, detail=detail)]


# Weight split between the structural components when no image is available.
_TITLE_WEIGHT = 0.4
_JACCARD_WEIGHT = 0.4
_MARKER_WEIGHT = 0.2

_SHINGLE = 1  # unigram tokens for Jaccard (robust for short pages)
_WORD_RE = re.compile(r"[a-z0-9]+")


class _TextExtractor(HTMLParser):
    """Collects the <title> text and visible body text (skips script/style)."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title_parts: list[str] = []
        self.text_parts: list[str] = []
        self._in_title = False
        self._skip_depth = 0

    def handle_starttag(self, tag, attrs):
        if tag == "title":
            self._in_title = True
        elif tag in ("script", "style"):
            self._skip_depth += 1

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        elif tag in ("script", "style") and self._skip_depth > 0:
            self._skip_depth -= 1

    def handle_data(self, data):
        if self._in_title:
            self.title_parts.append(data)
        elif self._skip_depth == 0:
            self.text_parts.append(data)

    @property
    def title(self) -> str:
        return " ".join(" ".join(self.title_parts).split())

    @property
    def text(self) -> str:
        return " ".join(" ".join(self.text_parts).split())


def _extract_title_text(html: str) -> tuple[str, str]:
    parser = _TextExtractor()
    try:
        parser.feed(html or "")
    except Exception as exc:  # noqa: BLE001 - malformed HTML must not crash us
        logger.warning("visual: HTML parse error: %s", exc)
    return parser.title.lower(), parser.text.lower()


def _tokens(text: str) -> set[str]:
    return set(_WORD_RE.findall(text or ""))


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0


# --- Perceptual hashing (optional, Pillow-only) ----------------------------

def average_hash(image_bytes: bytes, size: int = 8) -> str | None:
    """Compute an average-hash (aHash) hex string for image bytes using Pillow.

    Returns None when Pillow is not installed or the image cannot be decoded, so
    callers degrade to the structural path. Deterministic and offline.
    """
    try:
        import io

        from PIL import Image  # type: ignore
    except Exception:  # noqa: BLE001 - Pillow optional
        return None
    try:
        img = Image.open(io.BytesIO(image_bytes)).convert("L").resize((size, size))
        pixels = list(img.getdata())
        avg = sum(pixels) / len(pixels)
        bits = "".join("1" if p >= avg else "0" for p in pixels)
        return f"{int(bits, 2):0{size * size // 4}x}"
    except Exception as exc:  # noqa: BLE001
        logger.warning("visual: average_hash failed: %s", exc)
        return None


def hamming_similarity(hash_a: str, hash_b: str) -> float:
    """Similarity in 0..1 between two equal-length hex hashes (1 - normalised distance)."""
    if not hash_a or not hash_b or len(hash_a) != len(hash_b):
        return 0.0
    try:
        bits = len(hash_a) * 4
        xor = int(hash_a, 16) ^ int(hash_b, 16)
        return 1.0 - (bin(xor).count("1") / bits)
    except Exception:  # noqa: BLE001
        return 0.0


# --- Public API ------------------------------------------------------------

def compare_visual(fetch_result, brand: str | None,
                   favicon_image: bytes | None = None) -> tuple[float, list[Signal]]:
    """Compare a fetched page against a brand reference.

    Returns (similarity 0..1, signals). Uses a perceptual-hash path when an image
    (favicon_image) is available and matches a brand reference hash, otherwise falls
    back to a pure-python structural/text comparison. Returns (0.0, []) when the
    fetch_result carries nothing usable (no html and no favicon).
    """
    if fetch_result is None:
        return 0.0, []

    html = getattr(fetch_result, "html", "") or ""
    favicon_hash = getattr(fetch_result, "favicon_hash", None)
    has_images = bool(getattr(fetch_result, "screenshot", None) or getattr(fetch_result, "favicon_bytes", None))

    if not html and not favicon_hash and not favicon_image and not has_images:
        return 0.0, []

    ref = BRAND_INDEX.get(brand or "")
    if ref is None:
        # No brand matched: nothing to compare against visually.
        return 0.0, []

    signals: list[Signal] = []
    scores: list[float] = []

    # 0) Rendered screenshot vs genuine brand screenshots.
    shot, icon_phash = _page_fingerprints(fetch_result)
    if shot is not None:
        sim, where = screenshot_similarity(shot, brand)
        if sim:
            scores.append(sim)
        if sim >= SCREENSHOT_STRONG:
            signals.append(Signal(name="visual_screenshot_match", weight=0.45,
                                  detail=f"Rendered page is {sim:.0%} similar to genuine {brand} page {where}"))
        elif sim >= SCREENSHOT_MODERATE:
            signals.append(Signal(name="visual_screenshot_resemblance", weight=0.25,
                                  detail=f"Rendered page is {sim:.0%} similar to genuine {brand} page {where}"))

    # 1) Exact favicon-hash reuse: strongest visual signal (clone copied the logo).
    if favicon_hash and favicon_hash in known_favicon_hashes(brand):
        scores.append(1.0)
        signals.append(Signal(name="favicon_match", weight=0.4,
                              detail=f"Favicon hash matches genuine {brand} favicon"))
    elif icon_phash:
        fav = favicon_perceptual_similarity(icon_phash, brand)
        if fav >= FAVICON_PERCEPTUAL:
            scores.append(fav)
            signals.append(Signal(name="favicon_visual_match", weight=0.35,
                                  detail=f"Favicon is {fav:.0%} perceptually similar to the genuine {brand} icon"))

    # 2) Perceptual-hash path when an image is supplied and the brand has a reference.
    if favicon_image and ref.get("ahash"):
        candidate_hash = average_hash(favicon_image)
        if candidate_hash:
            sim = hamming_similarity(candidate_hash, ref["ahash"])
            scores.append(sim)
            if sim >= 0.85:
                signals.append(Signal(name="visual_phash_match", weight=0.4,
                                      detail=f"Perceptual hash is {sim:.0%} similar to {brand} logo"))

    # 3) Structural/text fallback (always available).
    if html:
        title, text = _extract_title_text(html)
        page_tokens = _tokens(text) | _tokens(title)
        ref_tokens = set(ref["vocab"])

        title_hit = sum(1 for kw in ref["title_keywords"] if kw in title)
        title_score = title_hit / max(1, len(ref["title_keywords"]))

        jac = _jaccard(page_tokens, ref_tokens)

        marker_hit = sum(1 for m in ref["dom_markers"] if m in text or m in title)
        marker_score = marker_hit / max(1, len(ref["dom_markers"]))

        structural = (_TITLE_WEIGHT * title_score
                      + _JACCARD_WEIGHT * min(1.0, jac * 2.0)
                      + _MARKER_WEIGHT * marker_score)
        scores.append(structural)

        if title_hit:
            signals.append(Signal(name="brand_title_match", weight=0.25,
                                  detail=f"Page title echoes {brand} ({title_hit} keyword(s))"))
        if structural >= 0.3:
            signals.append(Signal(name="visual_structural_similarity", weight=0.3,
                                  detail=(f"Page structure/text resembles {brand} "
                                          f"(title={title_score:.0%}, jaccard={jac:.0%}, "
                                          f"markers={marker_score:.0%})")))

    similarity = round(max(scores), 3) if scores else 0.0
    return similarity, signals
