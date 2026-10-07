"""Image fingerprinting primitives for the visual similarity engine.

Implemented with Pillow and numpy only (no OpenCV, no ML models, no GPU):

* ``phash``   - 64-bit DCT perceptual hash; robust to resizing, re-encoding and
                small colour shifts, which is what clone kits typically introduce.
* ``dhash``   - 64-bit gradient hash; complements pHash on layout changes.
* ``palette`` - normalised 64-bin colour histogram over non-background pixels,
                capturing brand colour identity (e.g. PhonePe purple).

All functions accept raw image bytes and return ``None`` when the image cannot be
decoded, so callers can degrade gracefully.
"""
from __future__ import annotations

import io
import logging
from dataclasses import asdict, dataclass

import numpy as np
from PIL import Image, ImageOps

logger = logging.getLogger(__name__)

_HASH_SIZE = 8
_PHASH_IMG = 32
_PALETTE_LEVELS = 4  # per channel -> 4^3 = 64 bins


def _open(data: bytes) -> Image.Image | None:
    try:
        img = Image.open(io.BytesIO(data))
        img.load()
    except Exception as exc:  # noqa: BLE001 - undecodable image
        logger.debug("imaging: cannot decode image: %s", exc)
        return None
    if img.mode in ("P", "LA", "RGBA") or "transparency" in img.info:
        # Flatten transparency onto white so icons with alpha hash consistently.
        rgba = img.convert("RGBA")
        background = Image.new("RGBA", rgba.size, (255, 255, 255, 255))
        img = Image.alpha_composite(background, rgba)
    return img.convert("RGB")


def _bits_to_hex(bits: np.ndarray) -> str:
    value = 0
    for bit in bits.flatten():
        value = (value << 1) | int(bit)
    return f"{value:0{bits.size // 4}x}"


def _dct_matrix(n: int) -> np.ndarray:
    k = np.arange(n)
    mat = np.cos(np.pi * (2 * k[None, :] + 1) * k[:, None] / (2 * n))
    mat[0, :] *= 1 / np.sqrt(2)
    return mat * np.sqrt(2 / n)


_DCT = _dct_matrix(_PHASH_IMG)


def phash(data: bytes) -> str | None:
    img = _open(data)
    if img is None:
        return None
    gray = np.asarray(ImageOps.grayscale(img).resize((_PHASH_IMG, _PHASH_IMG), Image.Resampling.LANCZOS),
                      dtype=np.float64)
    coeffs = _DCT @ gray @ _DCT.T
    low = coeffs[:_HASH_SIZE, :_HASH_SIZE]
    median = np.median(low.flatten()[1:])  # exclude the DC term
    return _bits_to_hex(low > median)


def dhash(data: bytes) -> str | None:
    img = _open(data)
    if img is None:
        return None
    gray = np.asarray(ImageOps.grayscale(img).resize((_HASH_SIZE + 1, _HASH_SIZE), Image.Resampling.LANCZOS),
                      dtype=np.int16)
    return _bits_to_hex(gray[:, 1:] > gray[:, :-1])


def palette(data: bytes, ignore_background: bool = True) -> list[float] | None:
    """64-bin colour histogram (sums to 1). Near-white and near-black pixels are
    ignored by default because they dominate every web page and carry no brand identity."""
    img = _open(data)
    if img is None:
        return None
    img.thumbnail((256, 256))
    px = np.asarray(img, dtype=np.int16).reshape(-1, 3)
    if ignore_background:
        bright = px.min(axis=1) > 235
        dark = px.max(axis=1) < 20
        greyish = (px.max(axis=1) - px.min(axis=1)) < 18
        keep = ~(bright | dark | greyish)
        if keep.sum() >= 50:
            px = px[keep]
    q = (px * _PALETTE_LEVELS) // 256
    idx = q[:, 0] * _PALETTE_LEVELS * _PALETTE_LEVELS + q[:, 1] * _PALETTE_LEVELS + q[:, 2]
    hist = np.bincount(idx, minlength=_PALETTE_LEVELS ** 3).astype(np.float64)
    total = hist.sum()
    return [round(float(v), 5) for v in (hist / total)] if total else None


def hash_similarity(a: str | None, b: str | None) -> float:
    """1 - normalised Hamming distance between two equal-length hex hashes (0 when unknown)."""
    if not a or not b or len(a) != len(b):
        return 0.0
    try:
        distance = (int(a, 16) ^ int(b, 16)).bit_count()
    except ValueError:
        return 0.0
    return 1.0 - distance / (len(a) * 4)


def palette_similarity(a: list[float] | None, b: list[float] | None) -> float:
    """Histogram intersection in 0..1."""
    if not a or not b or len(a) != len(b):
        return 0.0
    return float(np.minimum(np.asarray(a), np.asarray(b)).sum())


@dataclass
class Fingerprint:
    phash: str | None = None
    dhash: str | None = None
    palette: list[float] | None = None

    @classmethod
    def of(cls, data: bytes | None) -> Fingerprint | None:
        if not data:
            return None
        fp = cls(phash=phash(data), dhash=dhash(data), palette=palette(data))
        return fp if fp.phash else None

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: dict | None) -> Fingerprint | None:
        if not raw:
            return None
        return cls(phash=raw.get("phash"), dhash=raw.get("dhash"), palette=raw.get("palette"))


def layout_similarity(a: Fingerprint | None, b: Fingerprint | None) -> float:
    """Combined perceptual similarity of two page screenshots (pHash + dHash average)."""
    if a is None or b is None:
        return 0.0
    return (hash_similarity(a.phash, b.phash) + hash_similarity(a.dhash, b.dhash)) / 2
