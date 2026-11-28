"""Continuous automated pipeline worker (discover -> verify -> AI triage).

Runs inside the hardened Docker sandbox via `docker compose --profile auto up -d`
or locally for single-pass testing with `--once`.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from typing import Any, Callable, Dict, Optional, Sequence

from src.cert_collector import DEFAULT_MULTI_CT_LOGS, tail_multi_ct_logs
from src.db import SupabaseDB, load_dotenv
from src.discover import fetch_all_feeds
from src.verify import SafeBrowserVerifier, extract_clean_text

DEFAULT_VERIFY_INTERVAL_S = 10.0
DEFAULT_VERIFY_BATCH = 10
DEFAULT_VERIFY_CONCURRENCY = 4
DEFAULT_TRIAGE_BATCH = 10


async def run_discover_pass(
    db: Any,
    *,
    log_urls: Sequence[str] = DEFAULT_MULTI_CT_LOGS,
    backfill: int = 2000,
    duration_s: float = 20.0,
    limit: int = 30,
    include_feeds: bool = False,
    collector_fn: Optional[Callable[..., Any]] = None,
    feeds_fn: Optional[Callable[..., Any]] = None,
) -> Dict[str, Any]:
    """Collect fresh CT domains (and periodic OpenPhish/PhishingDB feeds) into Supabase."""
    collect = collector_fn or tail_multi_ct_logs
    candidates = await collect(
        log_urls=log_urls,
        backfill=backfill,
        duration_s=duration_s,
        limit=limit,
        verbose=False,
    )
    rows = [
        {
            "raw_url": f"https://{c.normalized_url}",
            "source": c.source,
            "ai_category": c.category_hint,
            "ai_note": f"CT match: {c.matched_rule}"[:140],
        }
        for c in candidates
    ]

    feed_found = 0
    if include_feeds:
        fetch_feeds = feeds_fn or fetch_all_feeds
        feed_items = await fetch_feeds(limit_per_feed=limit, indonesia_only=True, verbose=False)
        feed_found = len(feed_items)
        for item in feed_items:
            rows.append(
                {
                    "raw_url": item.raw_url if item.raw_url.startswith(("http://", "https://")) else f"https://{item.normalized_url}",
                    "source": item.source,
                    "ai_category": item.category_hint,
                    "ai_note": f"Feed match: {item.matched_rule}"[:140] if item.matched_rule else None,
                }
            )

    inserted = await asyncio.to_thread(db.insert_urls, rows, "ct_log", "new") if rows else []
    return {
        "stage": "discover",
        "found": len(candidates) + feed_found,
        "ct_found": len(candidates),
        "feed_found": feed_found,
        "inserted": len(inserted),
    }


async def run_verify_pass(
    db: Any,
    *,
    batch_size: int = DEFAULT_VERIFY_BATCH,
    concurrency: int = DEFAULT_VERIFY_CONCURRENCY,
    timeout_ms: int = 15000,
    verifier_factory: Optional[Callable[[], Any]] = None,
) -> Dict[str, Any]:
    """Fetch status='new' URLs, verify safely in Playwright, upload JPEG, and update DB."""
    queue = await asyncio.to_thread(db.fetch_queue, "new", batch_size)
    if not queue:
        return {"stage": "verify", "processed": 0, "verified": 0, "dead_or_blocked": 0}

    sem = asyncio.Semaphore(max(1, concurrency))
    make_verifier = verifier_factory or (
        lambda: SafeBrowserVerifier(
            timeout_ms=timeout_ms,
            uploader=db.upload_screenshot,
        )
    )

    per_url_hard_timeout = max(25.0, (timeout_ms / 1000.0) * 2.2)

    async def _one(verifier: Any, row: Dict[str, Any]) -> str:
        async with sem:
            try:
                res = await asyncio.wait_for(
                    verifier.verify_url(row["raw_url"], url_id=row["id"]),
                    timeout=per_url_hard_timeout,
                )
            except asyncio.TimeoutError:
                await asyncio.to_thread(
                    db.update_status,
                    row["id"],
                    "dead_or_blocked",
                    error_code="ERR_TARGET_TIMEOUT",
                    error_detail=f"Hard timeout after {int(per_url_hard_timeout)}s",
                )
                return "dead_or_blocked"
            clean_txt = extract_clean_text(res.raw_html or "") if res.raw_html else None
            await asyncio.to_thread(
                db.update_status,
                row["id"],
                res.status,
                final_url=res.final_url,
                final_normalized_url=res.final_normalized_url,
                http_status=res.http_status,
                page_title=res.page_title,
                clean_text=clean_txt,
                screenshot_path=res.screenshot_path,
                error_code=res.error_code,
                error_detail=res.error_detail,
            )
            return res.status

    async with make_verifier() as verifier:
        statuses = list(await asyncio.gather(*(_one(verifier, row) for row in queue)))

    verified_cnt = sum(1 for st in statuses if st == "verified")
    return {
        "stage": "verify",
        "processed": len(statuses),
        "verified": verified_cnt,
        "dead_or_blocked": len(statuses) - verified_cnt,
    }


async def run_reverify_approved_pass(
    db: Any,
    *,
    batch_size: int = 10,
    concurrency: int = DEFAULT_VERIFY_CONCURRENCY,
    timeout_ms: int = 9000,
    verifier_factory: Optional[Callable[[], Any]] = None,
) -> Dict[str, Any]:
    """Re-check oldest-updated status='approved' URLs; prune dead/Trust+ sites automatically."""
    def _fetch_oldest_approved() -> Any:
        try:
            return db.fetch_queue("approved", batch_size, order="updated_at.asc,id.asc")
        except TypeError:
            return db.fetch_queue("approved", batch_size)

    rows = await asyncio.to_thread(_fetch_oldest_approved)
    queue = [r for r in rows if r.get("batch_id") is None]
    if not queue:
        return {
            "stage": "reverify_approved",
            "processed": 0,
            "still_approved": 0,
            "dead_or_blocked": 0,
        }

    sem = asyncio.Semaphore(max(1, concurrency))
    make_verifier = verifier_factory or (
        lambda: SafeBrowserVerifier(
            timeout_ms=timeout_ms,
            uploader=db.upload_screenshot,
        )
    )

    per_url_hard_timeout = max(20.0, (timeout_ms / 1000.0) * 2.2)

    async def _one(verifier: Any, row: Dict[str, Any]) -> str:
        async with sem:
            target = (
                row.get("final_url")
                or row.get("final_normalized_url")
                or row.get("raw_url")
                or row.get("normalized_url")
                or ""
            )
            try:
                res = await asyncio.wait_for(
                    verifier.verify_url(target, url_id=row["id"]),
                    timeout=per_url_hard_timeout,
                )
            except asyncio.TimeoutError:
                await asyncio.to_thread(
                    db.update_status,
                    row["id"],
                    "dead_or_blocked",
                    error_code="ERR_TARGET_TIMEOUT",
                    error_detail=f"Hard timeout after {int(per_url_hard_timeout)}s",
                )
                return "dead_or_blocked"
            if res.status == "verified":
                fields: Dict[str, Any] = {
                    "final_url": res.final_url,
                    "final_normalized_url": res.final_normalized_url,
                    "http_status": res.http_status,
                    "error_code": None,
                    "error_detail": None,
                }
                if res.page_title:
                    fields["page_title"] = res.page_title
                if res.raw_html:
                    fields["clean_text"] = extract_clean_text(res.raw_html)
                if res.screenshot_path:
                    fields["screenshot_path"] = res.screenshot_path
                await asyncio.to_thread(db.update_status, row["id"], "approved", **fields)
                return "approved"

            await asyncio.to_thread(
                db.update_status,
                row["id"],
                "dead_or_blocked",
                http_status=res.http_status,
                error_code=res.error_code,
                error_detail=res.error_detail,
            )
            return "dead_or_blocked"

    async with make_verifier() as verifier:
        statuses = list(await asyncio.gather(*(_one(verifier, row) for row in queue)))

    still_approved = sum(1 for st in statuses if st == "approved")
    return {
        "stage": "reverify_approved",
        "processed": len(statuses),
        "still_approved": still_approved,
        "dead_or_blocked": len(statuses) - still_approved,
    }


_PIVOT_SKIP_SUFFIXES = (".ac.id", ".go.id", ".sch.id", ".desa.id", ".or.id", ".mil.id")
_PIVOT_ILLEGAL_CATEGORIES = frozenset({"judol", "pinjol", "phishing", "scam"})


async def run_triage_pass(
    db: Any,
    *,
    batch_size: int = DEFAULT_TRIAGE_BATCH,
    ai_client: Optional[Any] = None,
    auto_pivot: bool = False,
    pivot_min_confidence: float = 0.90,
    pivot_max_seeds: int = 2,
    pivot_max_candidates: int = 16,
    pivot_fn: Optional[Callable[..., Any]] = None,
) -> Dict[str, Any]:
    """Classify verified URLs via AI API (fail-open) and optionally DNS-pivot high-confidence hits."""
    from src.ai_triage import create_deepseek_client, triage_site

    load_dotenv()
    if ai_client is None:
        key = os.getenv("DEEPSEEK_API_KEY", "").strip()
        if not key or "your-deepseek" in key:
            return {"stage": "triage", "processed": 0, "skipped": "no_api_key"}
        try:
            ai_client = create_deepseek_client()
        except Exception as exc:
            return {"stage": "triage", "processed": 0, "skipped": str(exc)}

    rows = await asyncio.to_thread(db.fetch_queue, "verified", batch_size)
    if not rows:
        return {"stage": "triage", "processed": 0}

    processed = 0
    errors = 0
    pivot_seeds: list[tuple[str, str]] = []
    for row in rows:
        try:
            target_norm = str(row.get("final_normalized_url") or row.get("normalized_url") or "")
            res = await asyncio.to_thread(
                triage_site,
                target_norm,
                str(row.get("page_title") or ""),
                str(row.get("clean_text") or ""),
                client=ai_client,
                url_id=row["id"],
            )
            await asyncio.to_thread(
                db.update_status,
                row["id"],
                "triaged",
                ai_category=res.category,
                ai_confidence=res.confidence,
                ai_note=res.reason_140,
            )
            processed += 1
            if (
                auto_pivot
                and len(pivot_seeds) < pivot_max_seeds
                and res.category in _PIVOT_ILLEGAL_CATEGORIES
                and res.confidence >= pivot_min_confidence
            ):
                host = target_norm.split("/", 1)[0].lower()
                if host and not host.endswith(_PIVOT_SKIP_SUFFIXES):
                    pivot_seeds.append((host, res.category))
        except Exception as exc:
            errors += 1
            print(f"[worker:triage] id={row['id']} error: {exc}", file=sys.stderr, flush=True)

    result: Dict[str, Any] = {"stage": "triage", "processed": processed, "errors": errors}
    if auto_pivot:
        pivoted_inserted = 0
        if pivot_seeds:
            if pivot_fn is None:
                from src.dns_pivot import expand_from_seed
                pivot_caller = expand_from_seed
            else:
                pivot_caller = pivot_fn

            pivot_rows: list[dict[str, Any]] = []
            for seed_host, seed_cat in pivot_seeds:
                try:
                    siblings = await asyncio.wait_for(
                        pivot_caller(
                            seed_host,
                            number_window=4,
                            max_candidates=pivot_max_candidates,
                            timeout_s=2.5,
                            concurrency=8,
                            verbose=False,
                        ),
                        timeout=15.0,
                    )
                except Exception as exc:
                    print(f"[worker:pivot] seed={seed_host} error: {exc}", file=sys.stderr, flush=True)
                    continue
                for sib in siblings:
                    pivot_rows.append(
                        {
                            "raw_url": f"https://{sib.normalized_url}",
                            "source": "dns_pivot",
                            "ai_category": seed_cat,
                            "ai_note": f"DNS pivot from {seed_host}"[:140],
                        }
                    )
            if pivot_rows:
                inserted = await asyncio.to_thread(db.insert_urls, pivot_rows, "dns_pivot", "new")
                pivoted_inserted = len(inserted)
        result["pivoted_inserted"] = pivoted_inserted
    return result


async def _loop(
    mode: str,
    *,
    once: bool,
    discover_interval: float,
    verify_interval: float,
    triage_interval: float,
    verify_batch: int,
    verify_concurrency: int,
    backfill: int,
    collect_duration: float,
) -> int:
    with SupabaseDB.from_env() as db:
        if mode == "reverify":
            summary = await run_reverify_approved_pass(
                db,
                batch_size=max(verify_batch, 50),
                concurrency=verify_concurrency,
            )
            print(json.dumps(summary), flush=True)
            return 0

        cycle = 0
        while True:
            cycle += 1
            if mode in ("discover", "all"):
                try:
                    summary = await asyncio.wait_for(
                        run_discover_pass(
                            db,
                            backfill=backfill if cycle == 1 else min(backfill, 1500),
                            duration_s=collect_duration,
                            include_feeds=(cycle == 1 or cycle % 10 == 0),
                        ),
                        timeout=90.0,
                    )
                    print(json.dumps({"cycle": cycle, **summary}), flush=True)
                except Exception as exc:
                    print(f"[worker:discover] error: {exc}", file=sys.stderr, flush=True)

            if mode in ("verify", "all"):
                try:
                    summary = await asyncio.wait_for(
                        run_verify_pass(
                            db,
                            batch_size=verify_batch,
                            concurrency=verify_concurrency,
                        ),
                        timeout=120.0,
                    )
                    print(json.dumps({"cycle": cycle, **summary}), flush=True)
                except Exception as exc:
                    print(f"[worker:verify] error: {exc}", file=sys.stderr, flush=True)

            if mode in ("triage", "all"):
                try:
                    summary = await asyncio.wait_for(
                        run_triage_pass(db, auto_pivot=True),
                        timeout=90.0,
                    )
                    print(json.dumps({"cycle": cycle, **summary}), flush=True)
                except Exception as exc:
                    print(f"[worker:triage] error: {exc}", file=sys.stderr, flush=True)

            if once:
                return 0

            sleep_s = (
                discover_interval
                if mode == "discover"
                else verify_interval
                if mode == "verify"
                else triage_interval
                if mode == "triage"
                else min(discover_interval, verify_interval)
            )
            await asyncio.sleep(max(2.0, sleep_s))


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m src.worker",
        description="Automated background worker for discover, verify, and AI triage.",
    )
    parser.add_argument(
        "mode",
        choices=("discover", "verify", "triage", "reverify", "all"),
        default="all",
        nargs="?",
        help="Pipeline stages to run (default: all; use 'reverify' to re-check approved links).",
    )
    parser.add_argument("--once", action="store_true", help="Run a single cycle and exit.")
    parser.add_argument("--backfill", type=int, default=2000, help="CT backfill per log (default: 2000).")
    parser.add_argument("--collect-duration", type=float, default=20.0, help="CT scan seconds per cycle.")
    parser.add_argument("--verify-batch", type=int, default=DEFAULT_VERIFY_BATCH)
    parser.add_argument("--verify-concurrency", type=int, default=DEFAULT_VERIFY_CONCURRENCY)
    parser.add_argument("--interval", type=float, default=DEFAULT_VERIFY_INTERVAL_S, help="Sleep seconds between cycles.")
    args = parser.parse_args(argv)

    return asyncio.run(
        _loop(
            args.mode,
            once=args.once,
            discover_interval=args.interval,
            verify_interval=args.interval,
            triage_interval=args.interval,
            verify_batch=args.verify_batch,
            verify_concurrency=args.verify_concurrency,
            backfill=args.backfill,
            collect_duration=args.collect_duration,
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
