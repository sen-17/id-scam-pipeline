"""Unit tests for src.worker and multi-log CT collection."""

import json
from types import SimpleNamespace
import unittest

from src.cert_collector import CertCandidate
from src.worker import (
    run_discover_pass,
    run_reverify_approved_pass,
    run_triage_pass,
    run_verify_pass,
)
from tests.test_verify import _FakeBrowser, _FakePlaywrightCM


class _MemoryWorkerDB:
    def __init__(self):
        self.rows = []
        self.next_id = 1
        self.uploads = []

    def insert_urls(self, items, source="manual", status="new"):
        inserted = []
        existing = {r["normalized_url"] for r in self.rows}
        for item in items:
            raw = item if isinstance(item, str) else item["raw_url"]
            norm = raw.replace("https://", "")
            if norm in existing:
                continue
            existing.add(norm)
            row = {
                "id": self.next_id,
                "raw_url": raw,
                "normalized_url": norm,
                "source": item.get("source", source) if isinstance(item, dict) else source,
                "status": status,
                "page_title": None,
                "clean_text": None,
            }
            self.next_id += 1
            self.rows.append(row)
            inserted.append(row)
        return inserted

    def fetch_queue(self, status="new", limit=50):
        return [r for r in self.rows if r["status"] == status][:limit]

    def update_status(self, url_id, status=None, **fields):
        for r in self.rows:
            if r["id"] == url_id:
                if status is not None:
                    r["status"] = status
                r.update(fields)
                return r
        return None

    def upload_screenshot(self, path, data):
        self.uploads.append((path, len(data)))
        return path


class TestAutomatedWorker(unittest.IsolatedAsyncioTestCase):
    async def test_discover_verify_and_triage_single_cycle(self):
        db = _MemoryWorkerDB()

        async def fake_collect(**kwargs):
            return [
                CertCandidate(
                    normalized_url="slotbaru99.xyz",
                    raw_domain="slotbaru99.xyz",
                    source="ct_log",
                    category_hint="judol",
                    matched_rule="judol:slotgacor",
                )
            ]

        disc = await run_discover_pass(db, collector_fn=fake_collect)
        self.assertEqual(
            disc,
            {"stage": "discover", "found": 1, "ct_found": 1, "feed_found": 0, "inserted": 1},
        )
        self.assertEqual(len(db.rows), 1)
        self.assertEqual(db.rows[0]["status"], "new")

        async def fake_feeds(**kwargs):
            return [
                SimpleNamespace(
                    raw_url="https://bri-login-palsu.xyz",
                    normalized_url="bri-login-palsu.xyz",
                    source="openphish",
                    category_hint="phishing",
                    matched_rule="brand:bri",
                )
            ]

        disc_feeds = await run_discover_pass(
            db,
            collector_fn=fake_collect,
            feeds_fn=fake_feeds,
            include_feeds=True,
        )
        self.assertEqual(disc_feeds["ct_found"], 1)
        self.assertEqual(disc_feeds["feed_found"], 1)
        self.assertEqual(disc_feeds["inserted"], 1)
        # Keep only the original CT row for the rest of the single-cycle check
        db.rows = db.rows[:1]

        browser = _FakeBrowser(
            lambda u: {
                "final_url": "https://slotbaru99.xyz/daftar",
                "status": 200,
                "title": "Slot Baru 99",
                "html": "<html><body><h1>Slot Baru 99</h1><p>Deposit QRIS</p></body></html>",
                "screenshot": b"\xff\xd8\xffdemo",
            }
        )
        from src.verify import SafeBrowserVerifier

        ver = await run_verify_pass(
            db,
            verifier_factory=lambda: SafeBrowserVerifier(
                uploader=db.upload_screenshot,
                playwright_factory=lambda: _FakePlaywrightCM(browser),
            ),
        )
        self.assertEqual(ver, {"stage": "verify", "processed": 1, "verified": 1, "dead_or_blocked": 0})
        self.assertEqual(db.rows[0]["status"], "verified")
        self.assertEqual(db.rows[0]["screenshot_path"], "1_slotbaru99.xyz_daftar.jpg")
        self.assertIn("Deposit QRIS", db.rows[0]["clean_text"])

        fake_resp = SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(
                        content=json.dumps(
                            {
                                "category": "judol",
                                "confidence": 0.95,
                                "reason_140": "Situs slot online aktif dengan deposit QRIS.",
                            }
                        )
                    )
                )
            ]
        )

        class _FakeCompletions:
            def create(self, **kwargs):
                return fake_resp

        fake_ai = SimpleNamespace(chat=SimpleNamespace(completions=_FakeCompletions()))
        tri = await run_triage_pass(db, ai_client=fake_ai)
        self.assertEqual(tri, {"stage": "triage", "processed": 1, "errors": 0})
        self.assertEqual(db.rows[0]["status"], "triaged")
        self.assertEqual(db.rows[0]["ai_category"], "judol")
        self.assertEqual(db.rows[0]["ai_confidence"], 0.95)

    async def test_reverify_approved_keeps_live_and_prunes_dead_or_blocked(self):
        from src.verify import SafeBrowserVerifier

        db = _MemoryWorkerDB()
        db.rows = [
            {
                "id": 1,
                "raw_url": "https://masihhidup88.xyz",
                "normalized_url": "masihhidup88.xyz",
                "final_normalized_url": "masihhidup88.xyz",
                "status": "approved",
                "batch_id": None,
            },
            {
                "id": 2,
                "raw_url": "https://kenablokir99.xyz",
                "normalized_url": "kenablokir99.xyz",
                "final_normalized_url": "kenablokir99.xyz",
                "status": "approved",
                "batch_id": None,
            },
        ]

        def fake_page(url: str) -> dict:
            if "masihhidup88" in url:
                return {
                    "final_url": "https://masihhidup88.xyz/promo",
                    "status": 200,
                    "title": "Slot Masih Hidup",
                    "html": "<html><body><h1>Slot Masih Hidup</h1><p>Deposit QRIS</p></body></html>",
                    "screenshot": b"\xff\xd8\xffdemo",
                }
            return {
                "final_url": "https://trustpositif.komdigi.go.id/blocked",
                "status": 200,
                "title": "Internet Positif",
                "html": "<html><body>Situs ini diblokir oleh Komdigi Trust+</body></html>",
                "screenshot": b"\xff\xd8\xffdemo",
            }

        browser = _FakeBrowser(fake_page)
        summary = await run_reverify_approved_pass(
            db,
            verifier_factory=lambda: SafeBrowserVerifier(
                uploader=db.upload_screenshot,
                playwright_factory=lambda: _FakePlaywrightCM(browser),
            ),
        )
        self.assertEqual(
            summary,
            {
                "stage": "reverify_approved",
                "processed": 2,
                "still_approved": 1,
                "dead_or_blocked": 1,
            },
        )
        self.assertEqual(db.rows[0]["status"], "approved")
        self.assertEqual(db.rows[0]["final_normalized_url"], "masihhidup88.xyz/promo")
        self.assertEqual(db.rows[1]["status"], "dead_or_blocked")

    async def test_triage_auto_pivot_expands_high_conf_illegal_and_skips_ac_id(self):
        db = _MemoryWorkerDB()
        db.rows = [
            {
                "id": 1,
                "raw_url": "https://slotbaru88.xyz",
                "normalized_url": "slotbaru88.xyz",
                "final_normalized_url": "slotbaru88.xyz",
                "status": "verified",
                "page_title": "Slot Baru 88",
                "clean_text": "Daftar slot deposit qris",
            },
            {
                "id": 2,
                "raw_url": "https://kampus.ac.id/slot-gacor",
                "normalized_url": "kampus.ac.id/slot-gacor",
                "final_normalized_url": "kampus.ac.id/slot-gacor",
                "status": "verified",
                "page_title": "Slot Kampus",
                "clean_text": "Slot gacor maxwin",
            },
        ]
        db.next_id = 3

        fake_resp = SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(
                        content=json.dumps(
                            {
                                "category": "judol",
                                "confidence": 0.96,
                                "reason_140": "Situs slot online aktif.",
                            }
                        )
                    )
                )
            ]
        )

        class _FakeCompletions:
            def create(self, **kwargs):
                return fake_resp

        fake_ai = SimpleNamespace(chat=SimpleNamespace(completions=_FakeCompletions()))
        pivoted_seeds: list[str] = []

        async def fake_pivot(seed_host: str, **kwargs):
            pivoted_seeds.append(seed_host)
            return [SimpleNamespace(normalized_url="slotbaru89.xyz")]

        summary = await run_triage_pass(
            db,
            ai_client=fake_ai,
            auto_pivot=True,
            pivot_fn=fake_pivot,
        )
        self.assertEqual(summary["processed"], 2)
        self.assertEqual(summary["pivoted_inserted"], 1)
        self.assertEqual(pivoted_seeds, ["slotbaru88.xyz"])
        self.assertTrue(any(r["normalized_url"] == "slotbaru89.xyz" and r["source"] == "dns_pivot" for r in db.rows))


if __name__ == "__main__":
    unittest.main()
