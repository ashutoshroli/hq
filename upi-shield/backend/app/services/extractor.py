"""Pull URLs, UPI IDs and phone numbers out of SMS/WhatsApp text."""
import re

URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"']+", re.I)
UPI_RE = re.compile(r"\b[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}\b")  # handle has no dot after '@' (unlike emails)
PHONE_RE = re.compile(r"(?<!\d)(?:\+?91[\-\s]?)?[6-9]\d{9}(?!\d)")
# Telegram: t.me/<handle> links (optionally with https/http/www) and bare @mentions.
TELEGRAM_LINK_RE = re.compile(r"(?:https?://)?(?:www\.)?t(?:elegram)?\.me/(\+?[a-zA-Z0-9_]{3,})", re.I)
TELEGRAM_HANDLE_RE = re.compile(r"(?<![a-zA-Z0-9@._\-])@([a-zA-Z][a-zA-Z0-9_]{4,31})\b")


def extract(text: str) -> dict[str, list[str]]:
    urls = [u.rstrip(".,);") for u in URL_RE.findall(text)]
    upi = [m for m in UPI_RE.findall(text)]
    phones = [re.sub(r"\D", "", p)[-10:] for p in PHONE_RE.findall(text)]
    telegram = [h.lstrip("@") for h in TELEGRAM_LINK_RE.findall(text)]
    telegram += [h for h in TELEGRAM_HANDLE_RE.findall(text)]
    dedupe = lambda xs: list(dict.fromkeys(xs))  # noqa: E731
    return {"urls": dedupe(urls), "upi_ids": dedupe(upi),
            "phones": dedupe(phones), "telegram": dedupe(telegram)}
