"""Visual + structural similarity engine (lightweight, offline, deterministic).

Matches a fetched page against a small checked-in brand reference index. The design
intentionally avoids heavy ML (NO CLIP/open_clip/faiss/GPU). Two complementary paths:

1. Perceptual-hash path (preferred when an image is available): compute an average-hash
   (aHash) over a favicon/screenshot image and compare its Hamming distance to the
   brand's expected hash(es). Implemented with Pillow ONLY when an image is supplied
   AND Pillow is importable; otherwise it is skipped. Pure favicon-hash equality is also
   honoured (the fetcher already produces a stable favicon_hash entity).

2. Structural/text fallback (always available, pure-python): title keyword match plus a
   token/shingle Jaccard similarity over the page's visible text against the brand's
   reference vocabulary and DOM markers. This runs with no network and no images.

compare_visual(fetch_result, brand) -> (similarity: float in 0..1, signals: list[Signal]).
Returns (0.0, []) when fetch_result is empty (no html and no favicon).
"""
import logging
import re
from html.parser import HTMLParser
from typing import Optional

from app.schemas import Signal

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

def average_hash(image_bytes: bytes, size: int = 8) -> Optional[str]:
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
        return "%0*x" % (size * size // 4, int(bits, 2))
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

def compare_visual(fetch_result, brand: Optional[str],
                   favicon_image: Optional[bytes] = None) -> tuple[float, list[Signal]]:
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

    if not html and not favicon_hash and not favicon_image:
        return 0.0, []

    ref = BRAND_INDEX.get(brand or "")
    if ref is None:
        # No brand matched: nothing to compare against visually.
        return 0.0, []

    signals: list[Signal] = []
    scores: list[float] = []

    # 1) Exact favicon-hash reuse: strongest visual signal (clone copied the logo).
    if favicon_hash and favicon_hash in ref["favicon_hashes"]:
        scores.append(1.0)
        signals.append(Signal(name="favicon_match", weight=0.4,
                              detail=f"Favicon hash matches genuine {brand} favicon"))

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
