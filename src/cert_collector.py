"""Passive SSL Certificate Transparency collector.

Watches public Certificate Transparency logs to catch freshly issued Indonesian
online gambling (judol), unlicensed loan (pinjol), and bank/gov phishing domains:
- `tail` (recommended): reads official RFC 6962 CT logs directly (e.g. Cloudflare
  Nimbus, DigiCert, Google Argon) with no third-party proxy dependency.
- `crtsh`: queries crt.sh JSON API (subject to upstream slowness/rate limits).
- `stream`: connects to a CertStream WebSocket endpoint (self-hosted or public).
- `check`: tests domain classification offline.

Strictly passive and read-only: only queries public CT log endpoints.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import struct
import sys
import time
from typing import Any, AsyncIterator, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from src.normalizer import normalize_url

CRTSH_BASE_URL = "https://crt.sh/"
DEFAULT_CT_LOG_URL = os.getenv(
    "CT_LOG_URL", "https://ct.cloudflare.com/logs/nimbus2026"
)
DEFAULT_MULTI_CT_LOGS: Tuple[str, ...] = (
    "https://ct.cloudflare.com/logs/nimbus2026",
    "https://wyvern.ct.digicert.com/2026h2",
    "https://ct.googleapis.com/logs/us1/argon2026h2",
    "https://oak.ct.letsencrypt.org/2026h2",
)
DEFAULT_CERTSTREAM_URL = os.getenv("CERTSTREAM_URL", "wss://certstream.calidog.io/")
DEFAULT_CRTSH_DAYS = 7
DEFAULT_CRTSH_KEYWORDS = (
    "slotgacor",
    "judol",
    "maxwin",
    "togel",
    "pinjol",
    "brimo",
    "bansos",
)

# Legitimate Indonesian banking, e-wallet, gov, and major infra domains to ignore.
OFFICIAL_DOMAIN_SUFFIXES = (
    "bri.co.id",
    "bca.co.id",
    "bankmandiri.co.id",
    "bni.co.id",
    "bankbsi.co.id",
    "dana.id",
    "ovo.id",
    "gopay.co.id",
    "gojek.com",
    "shopee.co.id",
    "tokopedia.com",
    "bukalapak.com",
    "kominfo.go.id",
    "komdigi.go.id",
    "kemensos.go.id",
    "ojk.go.id",
    "pajak.go.id",
    "bpjs-kesehatan.go.id",
    "bpjsketenagakerjaan.go.id",
    "posindonesia.co.id",
    "jne.co.id",
    "jet.co.id",
    "sicepat.com",
    "imphnen.dev",
    "google.com",
    "googleapis.com",
    "cloudflare.com",
    "amazonaws.com",
    "microsoft.com",
    "github.com",
)

# High-signal Indonesian gambling tokens (matched cleanly against domain text/tokens).
JUDOL_KEYWORDS = (
    "slotgacor",
    "gacor",
    "judol",
    "judionline",
    "situsjudi",
    "maxwin",
    "mahjongways",
    "pragmatic",
    "pgsoft",
    "sbobet",
    "sabungayam",
    "togel",
    "toto88",
    "toto4d",
    "slot88",
    "slot77",
    "slot777",
    "slot99",
    "bola88",
    "hoki88",
    "cuan88",
    "jp88",
    "poker88",
    "dominoqq",
    "angkajitu",
    "bocoranrtp",
    "linkalternatif",
    "pengeluaranhk",
    "pengeluaransgp",
    "bandartogel",
    "bandarslot",
    "rajagacor",
    "dewaslot",
    "zeus88",
    "olympus88",
)

# High-signal Indonesian unlicensed loan tokens.
PINJOL_KEYWORDS = (
    "pinjol",
    "pinjamanonline",
    "danacepat",
    "danakilat",
    "kreditcepat",
    "caircepat",
    "rupiahcepat",
    "uangkilat",
    "pinjamduit",
    "pinjamuang",
    "ktpcair",
    "danainstan",
)

# Phishing detection requires BOTH a brand token AND a lure token on a non-official domain
# to avoid false positives on unrelated words (e.g., "library" or "banana").
PHISHING_BRAND_TOKENS = frozenset(
    {
        "brimo",
        "bri",
        "mybca",
        "klikbca",
        "bca",
        "livin",
        "mandiri",
        "bni",
        "bsi",
        "dana",
        "ovo",
        "gopay",
        "shopeepay",
        "bansos",
        "bpjs",
        "dukcapil",
        "etilang",
        "pajak",
        "jne",
        "jnt",
        "posindo",
    }
)

PHISHING_LURE_TOKENS = frozenset(
    {
        "verifikasi",
        "verif",
        "aktivasi",
        "blokir",
        "tarif",
        "update",
        "klaim",
        "claim",
        "hadiah",
        "bantuan",
        "cair",
        "resmi",
        "daftar",
        "login",
        "akun",
        "kupon",
        "gebyar",
        "undian",
        "subsidi",
        "tagihan",
        "paket",
        "resi",
        "kurir",
        "pelayanan",
        "cek",
        "baru",
        "promo",
    }
)

_TOKEN_SPLIT_RE = re.compile(r"[^a-z0-9]+")


@dataclass(frozen=True)
class CertCandidate:
    normalized_url: str
    raw_domain: str
    source: str
    category_hint: str
    matched_rule: str
    issued_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def is_official_domain(domain: str) -> bool:
    host = domain.lower().strip(".")
    return any(
        host == suffix or host.endswith(f".{suffix}")
        for suffix in OFFICIAL_DOMAIN_SUFFIXES
    )


def _strip_wildcard(raw_domain: str) -> str:
    cleaned = raw_domain.strip().lower()
    while cleaned.startswith("*."):
        cleaned = cleaned[2:]
    return cleaned.rstrip(".")


def _domain_labels_without_tld(domain: str) -> Tuple[str, Set[str]]:
    parts = domain.lower().split(".")
    body_parts = parts[:-1] if len(parts) > 1 else parts
    joined = ".".join(body_parts)
    tokens = {tok for tok in _TOKEN_SPLIT_RE.split(joined) if tok}
    return joined, tokens


def _matches_brand_and_lure(tokens: Set[str]) -> Optional[Tuple[str, str]]:
    matched_brand: Optional[str] = None
    matched_lure: Optional[str] = None

    for tok in sorted(tokens):
        base = tok.rstrip("0123456789") or tok
        if matched_brand is None and base in PHISHING_BRAND_TOKENS:
            matched_brand = base
        elif matched_lure is None and base in PHISHING_LURE_TOKENS:
            matched_lure = base

    if matched_brand and matched_lure:
        return matched_brand, matched_lure
    return None


def classify_domain(raw_domain: str) -> Optional[Tuple[str, str, str]]:
    """Normalize a certificate domain and classify it against threat patterns.

    Returns `(normalized_url, category_hint, matched_rule)` or `None` if benign/invalid.
    """
    stripped = _strip_wildcard(raw_domain)
    norm = normalize_url(stripped)
    if not norm.ok or not norm.normalized:
        return None

    domain = norm.normalized
    if is_official_domain(domain):
        return None

    joined, tokens = _domain_labels_without_tld(domain)
    compact = joined.replace(".", "").replace("-", "")

    for kw in JUDOL_KEYWORDS:
        if kw in compact:
            return domain, "judol", f"judol:{kw}"

    for kw in PINJOL_KEYWORDS:
        if kw in compact:
            return domain, "pinjol", f"pinjol:{kw}"

    phish = _matches_brand_and_lure(tokens)
    if phish is not None:
        brand, lure = phish
        return domain, "phishing", f"phishing:{brand}+{lure}"

    return None


def extract_domains_from_ct_entry(entry: Dict[str, Any]) -> Tuple[List[str], Optional[str]]:
    """Decode an RFC 6962 CT log entry (X509 or Precert) into SAN DNS names + timestamp."""
    from cryptography import x509

    leaf_b64 = entry.get("leaf_input")
    if not leaf_b64:
        return [], None

    try:
        leaf = base64.b64decode(leaf_b64)
        if len(leaf) < 15:
            return [], None
        timestamp_ms = struct.unpack("!Q", leaf[2:10])[0]
        issued_at = datetime.fromtimestamp(
            timestamp_ms / 1000.0, tz=timezone.utc
        ).isoformat()
        entry_type = struct.unpack("!H", leaf[10:12])[0]

        if entry_type == 0:
            cert_len = int.from_bytes(leaf[12:15], "big")
            cert_der = leaf[15 : 15 + cert_len]
        elif entry_type == 1:
            extra_b64 = entry.get("extra_data")
            if not extra_b64:
                return [], issued_at
            extra = base64.b64decode(extra_b64)
            if len(extra) < 3:
                return [], issued_at
            cert_len = int.from_bytes(extra[0:3], "big")
            cert_der = extra[3 : 3 + cert_len]
        else:
            return [], issued_at

        cert = x509.load_der_x509_certificate(cert_der)
    except Exception:
        return [], None

    domains: List[str] = []
    try:
        san = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        domains.extend(san.value.get_values_for_type(x509.DNSName))
    except Exception:
        pass

    if not domains:
        try:
            for attr in cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME):
                if isinstance(attr.value, str):
                    domains.append(attr.value)
        except Exception:
            pass

    return domains, issued_at


def parse_ct_entries(
    entries: Sequence[Dict[str, Any]],
    source: str = "ct_log",
    seen: Optional[Set[str]] = None,
) -> Tuple[List[CertCandidate], int]:
    """Filter RFC 6962 CT entries into CertCandidate items; returns `(hits, domain_count)`."""
    dedupe = seen if seen is not None else set()
    results: List[CertCandidate] = []
    domain_count = 0

    for entry in entries:
        domains, issued_at = extract_domains_from_ct_entry(entry)
        domain_count += len(domains)
        for raw_name in domains:
            classified = classify_domain(raw_name)
            if classified is None:
                continue
            normalized, category, rule = classified
            if normalized in dedupe:
                continue
            dedupe.add(normalized)
            results.append(
                CertCandidate(
                    normalized_url=normalized,
                    raw_domain=raw_name.strip(),
                    source=source,
                    category_hint=category,
                    matched_rule=rule,
                    issued_at=issued_at,
                )
            )
    return results, domain_count


def _parse_iso_datetime(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def parse_crtsh_entries(
    entries: Sequence[Dict[str, Any]],
    max_age_days: Optional[int] = DEFAULT_CRTSH_DAYS,
    now: Optional[datetime] = None,
    seen: Optional[Set[str]] = None,
) -> List[CertCandidate]:
    """Extract, filter, normalize, and dedupe candidates from crt.sh JSON rows."""
    cutoff: Optional[datetime] = None
    if max_age_days is not None:
        ref = now or datetime.now(timezone.utc)
        cutoff = ref - timedelta(days=max_age_days)

    dedupe = seen if seen is not None else set()
    results: List[CertCandidate] = []

    for row in entries:
        issued_raw = row.get("entry_timestamp") or row.get("not_before")
        if cutoff is not None and issued_raw:
            issued_dt = _parse_iso_datetime(str(issued_raw))
            if issued_dt is not None and issued_dt < cutoff:
                continue

        name_value = str(row.get("name_value") or "")
        common_name = str(row.get("common_name") or "")
        raw_names = [n for n in name_value.splitlines() if n.strip()]
        if common_name.strip():
            raw_names.append(common_name.strip())

        for raw_name in raw_names:
            classified = classify_domain(raw_name)
            if classified is None:
                continue
            normalized, category, rule = classified
            if normalized in dedupe:
                continue
            dedupe.add(normalized)
            results.append(
                CertCandidate(
                    normalized_url=normalized,
                    raw_domain=raw_name.strip(),
                    source="crtsh",
                    category_hint=category,
                    matched_rule=rule,
                    issued_at=str(issued_raw) if issued_raw else None,
                )
            )
    return results


def parse_certstream_message(
    raw_message: str,
    seen: Optional[Set[str]] = None,
) -> List[CertCandidate]:
    """Parse one CertStream WebSocket JSON frame into filtered CertCandidate items."""
    try:
        payload = json.loads(raw_message)
    except (TypeError, ValueError):
        return []

    if not isinstance(payload, dict) or payload.get("message_type") != "certificate_update":
        return []

    data = payload.get("data") or {}
    leaf = data.get("leaf_cert") or {}
    all_domains = leaf.get("all_domains") or []
    if not isinstance(all_domains, list):
        return []

    seen_ts = data.get("seen")
    issued_at: Optional[str] = None
    if isinstance(seen_ts, (int, float)):
        issued_at = datetime.fromtimestamp(seen_ts, tz=timezone.utc).isoformat()

    dedupe = seen if seen is not None else set()
    results: List[CertCandidate] = []
    for raw_name in all_domains:
        if not isinstance(raw_name, str):
            continue
        classified = classify_domain(raw_name)
        if classified is None:
            continue
        normalized, category, rule = classified
        if normalized in dedupe:
            continue
        dedupe.add(normalized)
        results.append(
            CertCandidate(
                normalized_url=normalized,
                raw_domain=raw_name.strip(),
                source="certstream",
                category_hint=category,
                matched_rule=rule,
                issued_at=issued_at,
            )
        )
    return results


async def tail_ct_log(
    log_url: str = DEFAULT_CT_LOG_URL,
    backfill: int = 2000,
    duration_s: Optional[float] = 30.0,
    limit: Optional[int] = None,
    chunk_size: int = 100,
    concurrency: int = 8,
    poll_interval_s: float = 2.0,
    verbose: bool = True,
) -> AsyncIterator[CertCandidate]:
    """Tail an RFC 6962 Certificate Transparency log directly via HTTP.

    Starts `backfill` entries behind the current tree head, scans in parallel
    batches, and continues polling new entries until `duration_s` or `limit`.
    """
    import httpx

    base = log_url.rstrip("/")
    seen: Set[str] = set()
    yielded = 0
    scanned_certs = 0
    scanned_domains = 0
    deadline = (
        time.monotonic() + duration_s
        if duration_s is not None and duration_s > 0
        else None
    )
    sem = asyncio.Semaphore(max(1, concurrency))
    headers = {"User-Agent": "id-scam-pipeline/0.1 (passive CT tailer)"}

    async with httpx.AsyncClient(timeout=15.0, headers=headers) as client:
        sth_resp = await client.get(f"{base}/ct/v1/get-sth")
        sth_resp.raise_for_status()
        tree_size = int(sth_resp.json()["tree_size"])
        cursor = max(0, tree_size - max(0, backfill))

        if verbose:
            print(
                f"[ct-tail] connected to {base} (tree_size={tree_size}, start={cursor})",
                file=sys.stderr,
                flush=True,
            )

        async def _fetch_range(start_idx: int, end_idx: int) -> List[Dict[str, Any]]:
            async with sem:
                resp = await client.get(
                    f"{base}/ct/v1/get-entries",
                    params={"start": start_idx, "end": end_idx},
                )
                if resp.status_code != 200:
                    return []
                payload = resp.json()
                entries = payload.get("entries", [])
                return entries if isinstance(entries, list) else []

        while True:
            if limit is not None and yielded >= limit:
                break
            if deadline is not None and time.monotonic() >= deadline:
                break

            if cursor >= tree_size:
                if deadline is not None and time.monotonic() >= deadline:
                    break
                sleep_for = poll_interval_s
                if deadline is not None:
                    sleep_for = min(sleep_for, max(0.0, deadline - time.monotonic()))
                if sleep_for > 0:
                    await asyncio.sleep(sleep_for)
                try:
                    sth = await client.get(f"{base}/ct/v1/get-sth")
                    if sth.status_code == 200:
                        tree_size = int(sth.json()["tree_size"])
                except Exception as exc:
                    if verbose:
                        print(f"[ct-tail] get-sth error: {exc}", file=sys.stderr, flush=True)
                continue

            # Fetch up to `concurrency * chunk_size` entries per wave.
            wave_end = min(tree_size, cursor + (chunk_size * concurrency))
            ranges = [
                (s, min(wave_end - 1, s + chunk_size - 1))
                for s in range(cursor, wave_end, chunk_size)
            ]
            batches = await asyncio.gather(*(_fetch_range(s, e) for s, e in ranges))

            advanced = 0
            for batch in batches:
                if not batch:
                    continue
                advanced += len(batch)
                hits, dom_cnt = parse_ct_entries(batch, source="ct_log", seen=seen)
                scanned_certs += len(batch)
                scanned_domains += dom_cnt
                for item in hits:
                    yield item
                    yielded += 1
                    if limit is not None and yielded >= limit:
                        break
                if limit is not None and yielded >= limit:
                    break

            cursor = wave_end if advanced == 0 else cursor + advanced
            if verbose:
                print(
                    f"[ct-tail] scanned={scanned_certs} certs ({scanned_domains} domains), matched={yielded}",
                    file=sys.stderr,
                    flush=True,
                )


async def tail_multi_ct_logs(
    log_urls: Sequence[str] = DEFAULT_MULTI_CT_LOGS,
    backfill: int = 2000,
    duration_s: Optional[float] = 20.0,
    limit: Optional[int] = 25,
    concurrency_per_log: int = 4,
    verbose: bool = False,
) -> List[CertCandidate]:
    """Tail multiple official RFC 6962 CT logs in parallel and return deduped hits."""
    if not log_urls:
        return []

    per_log_limit = limit if limit is not None else None

    async def _collect_one(url: str) -> List[CertCandidate]:
        items: List[CertCandidate] = []
        try:
            async for hit in tail_ct_log(
                log_url=url,
                backfill=backfill,
                duration_s=duration_s,
                limit=per_log_limit,
                concurrency=concurrency_per_log,
                verbose=verbose,
            ):
                items.append(hit)
        except Exception as exc:
            if verbose:
                print(f"[ct-multi] {url} error: {exc}", file=sys.stderr, flush=True)
        return items

    batches = await asyncio.gather(*(_collect_one(u) for u in log_urls))
    seen: Set[str] = set()
    merged: List[CertCandidate] = []
    for batch in batches:
        for item in batch:
            if item.normalized_url in seen:
                continue
            seen.add(item.normalized_url)
            merged.append(item)
            if limit is not None and len(merged) >= limit:
                return merged
    return merged


async def fetch_crtsh(
    keywords: Iterable[str] = DEFAULT_CRTSH_KEYWORDS,
    max_age_days: Optional[int] = DEFAULT_CRTSH_DAYS,
    timeout_s: float = 25.0,
    delay_s: float = 1.5,
    limit: Optional[int] = None,
    verbose: bool = True,
) -> List[CertCandidate]:
    """Query public crt.sh JSON API passively across one or more keywords."""
    import httpx

    seen: Set[str] = set()
    collected: List[CertCandidate] = []
    headers = {"User-Agent": "id-scam-pipeline/0.1 (passive CT monitor)"}

    async with httpx.AsyncClient(timeout=timeout_s, headers=headers, follow_redirects=True) as client:
        keyword_list = list(keywords)
        for idx, kw in enumerate(keyword_list):
            if limit is not None and len(collected) >= limit:
                break
            params = {"q": f"%{kw}%", "output": "json"}
            if verbose:
                print(f"[crtsh] querying keyword={kw!r}...", file=sys.stderr, flush=True)
            try:
                resp = await client.get(CRTSH_BASE_URL, params=params)
                if resp.status_code == 200:
                    data = resp.json()
                    if isinstance(data, list):
                        batch = parse_crtsh_entries(
                            data,
                            max_age_days=max_age_days,
                            seen=seen,
                        )
                        if limit is not None:
                            remaining = limit - len(collected)
                            batch = batch[:remaining]
                        collected.extend(batch)
                        if verbose:
                            print(
                                f"[crtsh] keyword={kw!r} raw={len(data)} matched={len(batch)}",
                                file=sys.stderr,
                                flush=True,
                            )
                else:
                    print(
                        f"[crtsh] keyword={kw!r} HTTP {resp.status_code}, skipping.",
                        file=sys.stderr,
                        flush=True,
                    )
            except Exception as exc:
                print(
                    f"[crtsh] keyword={kw!r} failed ({exc}). Tip: use `tail` mode if crt.sh is overloaded.",
                    file=sys.stderr,
                    flush=True,
                )

            if idx + 1 < len(keyword_list) and delay_s > 0:
                await asyncio.sleep(delay_s)

    return collected


async def stream_certstream(
    ws_url: str = DEFAULT_CERTSTREAM_URL,
    duration_s: Optional[float] = None,
    limit: Optional[int] = None,
    max_backoff_s: float = 60.0,
    verbose: bool = True,
) -> AsyncIterator[CertCandidate]:
    """Stream real-time CT updates from a CertStream WebSocket with bounded backoff."""
    import websockets

    seen: Set[str] = set()
    yielded = 0
    frames = 0
    backoff = 2.0
    deadline = (
        time.monotonic() + duration_s
        if duration_s is not None and duration_s > 0
        else None
    )

    while True:
        if limit is not None and yielded >= limit:
            return
        if deadline is not None and time.monotonic() >= deadline:
            return

        try:
            async with websockets.connect(
                ws_url,
                ping_interval=20,
                ping_timeout=20,
                max_size=2**22,
            ) as ws:
                backoff = 2.0
                if verbose:
                    print(f"[certstream] connected to {ws_url}", file=sys.stderr, flush=True)
                warned_silent = False
                connected_at = time.monotonic()

                while True:
                    if limit is not None and yielded >= limit:
                        return
                    wait_timeout: Optional[float] = 10.0
                    if deadline is not None:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            return
                        wait_timeout = min(remaining, 10.0)

                    try:
                        raw_msg = await asyncio.wait_for(ws.recv(), timeout=wait_timeout)
                    except asyncio.TimeoutError:
                        if verbose and frames == 0 and not warned_silent and (time.monotonic() - connected_at) >= 10:
                            warned_silent = True
                            print(
                                "[certstream] 0 frames received after 10s. Public server may be idle; use `tail` mode instead.",
                                file=sys.stderr,
                                flush=True,
                            )
                        continue

                    frames += 1
                    if isinstance(raw_msg, bytes):
                        raw_msg = raw_msg.decode("utf-8", errors="ignore")

                    for item in parse_certstream_message(raw_msg, seen=seen):
                        yield item
                        yielded += 1
                        if limit is not None and yielded >= limit:
                            return
        except Exception as exc:
            print(
                f"[certstream] disconnected ({exc}); reconnecting in {backoff:.0f}s.",
                file=sys.stderr,
                flush=True,
            )
            sleep_for = backoff
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return
                sleep_for = min(sleep_for, remaining)
            await asyncio.sleep(sleep_for)
            backoff = min(backoff * 2.0, max_backoff_s)


def _emit_candidate(item: CertCandidate, out_fp: Optional[Any]) -> None:
    line = json.dumps(item.to_dict(), ensure_ascii=False)
    print(line, flush=True)
    if out_fp is not None:
        out_fp.write(line + "\n")
        out_fp.flush()


async def _run_tail_cli(args: argparse.Namespace) -> int:
    out_fp = args.out_file.open("a", encoding="utf-8") if args.out_file else None
    try:
        async for item in tail_ct_log(
            log_url=args.log_url,
            backfill=args.backfill,
            duration_s=args.duration,
            limit=args.limit,
            concurrency=args.concurrency,
            verbose=not args.quiet,
        ):
            _emit_candidate(item, out_fp)
    finally:
        if out_fp is not None:
            out_fp.close()
    return 0


async def _run_crtsh_cli(args: argparse.Namespace) -> int:
    items = await fetch_crtsh(
        keywords=args.keywords,
        max_age_days=args.days,
        limit=args.limit,
        verbose=not args.quiet,
    )
    out_fp = args.out_file.open("a", encoding="utf-8") if args.out_file else None
    try:
        for item in items:
            _emit_candidate(item, out_fp)
    finally:
        if out_fp is not None:
            out_fp.close()
    return 0


async def _run_stream_cli(args: argparse.Namespace) -> int:
    out_fp = args.out_file.open("a", encoding="utf-8") if args.out_file else None
    try:
        async for item in stream_certstream(
            ws_url=args.ws_url,
            duration_s=args.duration,
            limit=args.limit,
            verbose=not args.quiet,
        ):
            _emit_candidate(item, out_fp)
    finally:
        if out_fp is not None:
            out_fp.close()
    return 0


def _run_check_cli(domains: Sequence[str]) -> int:
    for raw in domains:
        hit = classify_domain(raw)
        if hit is None:
            print(f"SKIP  | {raw}")
        else:
            normalized, category, rule = hit
            print(f"MATCH | {raw} -> {normalized} [{category} | {rule}]")
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m src.cert_collector",
        description="Passive SSL Certificate Transparency collector (direct CT tail, crt.sh, CertStream).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_tail = sub.add_parser("tail", help="Tail an official RFC 6962 CT log directly (recommended).")
    p_tail.add_argument("--log-url", default=DEFAULT_CT_LOG_URL, help="CT log base URL.")
    p_tail.add_argument("--backfill", type=int, default=2000, help="Recent entries to scan on start (default: 2000).")
    p_tail.add_argument("--duration", type=float, default=30.0, help="Run duration in seconds (0 = unlimited).")
    p_tail.add_argument("--limit", type=int, default=50, help="Stop after N matched candidates.")
    p_tail.add_argument("--concurrency", type=int, default=8, help="Parallel chunk requests (default: 8).")
    p_tail.add_argument("--out-file", type=Path, default=None, help="Optional JSONL output file.")
    p_tail.add_argument("--quiet", action="store_true", help="Suppress stderr progress logs.")

    p_crtsh = sub.add_parser("crtsh", help="Query recent certificates from crt.sh.")
    p_crtsh.add_argument("--keywords", nargs="+", default=list(DEFAULT_CRTSH_KEYWORDS))
    p_crtsh.add_argument("--days", type=int, default=DEFAULT_CRTSH_DAYS)
    p_crtsh.add_argument("--limit", type=int, default=100)
    p_crtsh.add_argument("--out-file", type=Path, default=None)
    p_crtsh.add_argument("--quiet", action="store_true")

    p_stream = sub.add_parser("stream", help="Listen to a CertStream WebSocket feed.")
    p_stream.add_argument("--ws-url", default=DEFAULT_CERTSTREAM_URL)
    p_stream.add_argument("--duration", type=float, default=60.0)
    p_stream.add_argument("--limit", type=int, default=100)
    p_stream.add_argument("--out-file", type=Path, default=None)
    p_stream.add_argument("--quiet", action="store_true")

    p_check = sub.add_parser("check", help="Test domain keyword matching offline.")
    p_check.add_argument("domains", nargs="+")

    args = parser.parse_args(argv)
    if args.command == "tail":
        return asyncio.run(_run_tail_cli(args))
    if args.command == "crtsh":
        return asyncio.run(_run_crtsh_cli(args))
    if args.command == "stream":
        return asyncio.run(_run_stream_cli(args))
    return _run_check_cli(args.domains)


if __name__ == "__main__":
    raise SystemExit(main())
