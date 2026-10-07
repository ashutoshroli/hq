"""Pull URLs, UPI IDs and phone numbers out of SMS/WhatsApp text."""
import re

URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"']+", re.I)
UPI_RE = re.compile(r"\b[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}\b")  # handle has no dot after '@' (unlike emails)
PHONE_RE = re.compile(r"(?<!\d)(?:\+?91[\-\s]?)?[6-9]\d{9}(?!\d)")
# Telegram: t.me/<handle> links (optionally with https/http/www) and bare @mentions.
TELEGRAM_LINK_RE = re.compile(r"(?:https?://)?(?:www\.)?t(?:elegram)?\.me/(\+?[a-zA-Z0-9_]{3,})", re.I)
TELEGRAM_HANDLE_RE = re.compile(r"(?<![a-zA-Z0-9@._\-])@([a-zA-Z][a-zA-Z0-9_]{4,31})\b")


# Bare domains such as "sbi-kyc.top/update" (SMS lures often omit the scheme). Accepted
# only when the suffix is a real public suffix and the token is not part of an e-mail.
BARE_DOMAIN_RE = re.compile(
    r"(?<![@\w.:/-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})(/[^\s<>\"']*)?(?![\w@-])", re.I)
_FILE_EXTENSIONS = {"apk", "pdf", "jpg", "jpeg", "png", "gif", "txt", "doc", "docx", "xls", "xlsx", "zip", "exe",
                    "html", "htm", "php", "js", "json", "xml", "csv", "mp4", "mp3"}


def _bare_domains(text: str, known: list[str]) -> list[str]:
    from app.services.url_features import has_public_suffix, host_of

    seen_hosts = {host_of(u) for u in known}
    found = []
    for host, path in BARE_DOMAIN_RE.findall(text):
        host = host.lower().rstrip(".")
        if host.rsplit(".", 1)[-1] in _FILE_EXTENSIONS or host in seen_hosts or not has_public_suffix(host):
            continue
        seen_hosts.add(host)
        found.append(f"http://{host}{(path or '').rstrip('.,);')}")
    return found


def extract(text: str) -> dict[str, list[str]]:
    urls = [u.rstrip(".,);") for u in URL_RE.findall(text)]
    urls = [u if "://" in u else "http://" + u for u in urls]
    urls += _bare_domains(URL_RE.sub(" ", text), urls)
    upi = [m for m in UPI_RE.findall(text)]
    phones = [re.sub(r"\D", "", p)[-10:] for p in PHONE_RE.findall(text)]
    telegram = [h.lstrip("@") for h in TELEGRAM_LINK_RE.findall(text)]
    telegram += [h for h in TELEGRAM_HANDLE_RE.findall(text)]
    dedupe = lambda xs: list(dict.fromkeys(xs))  # noqa: E731
    return {"urls": dedupe(urls), "upi_ids": dedupe(upi),
            "phones": dedupe(phones), "telegram": dedupe(telegram)}
