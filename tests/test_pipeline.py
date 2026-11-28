"""Unit tests for db.py, screenshot compression/upload, ai_triage.py, and app.py."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
import json
from pathlib import Path
import random
import tempfile
import threading
from types import SimpleNamespace
import unittest

import httpx
from PIL import Image

from src.ai_triage import (
    DEFAULT_BATCH_SIZE,
    MAX_REASON_LEN,
    export_batch_prompts,
    import_batch_response,
    parse_batch_response,
    triage_site,
    write_batch_prompts,
)
from src.db import SupabaseDB
from src.verify import (
    DEFAULT_MAX_SCREENSHOT_BYTES,
    SafeBrowserVerifier,
    compress_jpeg_to_limit,
)
from tests.test_verify import _FakeBrowser, _FakePlaywrightCM


def _make_large_noisy_jpeg(width: int = 1280, height: int = 720) -> bytes:
    """Create a deterministic high-entropy JPEG larger than 150 KB."""
    rng = random.Random(42)
    pixels = bytes(rng.getrandbits(8) for _ in range(width * height * 3))
    img = Image.frombytes("RGB", (width, height), pixels)
    buf = BytesIO()
    img.save(buf, format="JPEG", quality=92)
    return buf.getvalue()


class TestSupabaseDB(unittest.TestCase):
    def test_insert_queue_update_lock_export_and_upload(self):
        captured: list[tuple[str, str, dict, object]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            qs = dict(request.url.params)
            body = json.loads(request.content.decode()) if request.headers.get("content-type", "").startswith("application/json") and request.content else request.content
            captured.append((request.method, path, qs, body))

            if request.method == "POST" and path == "/rest/v1/urls":
                self.assertEqual(qs.get("on_conflict"), "normalized_url")
                self.assertIn("resolution=ignore-duplicates", request.headers.get("Prefer", ""))
                # Simulate DB returning only newly inserted rows
                return httpx.Response(201, json=[{"id": 1, **body[0]}])

            if request.method == "GET" and path == "/rest/v1/urls":
                self.assertEqual(qs.get("status"), "eq.new")
                return httpx.Response(200, json=[{"id": 1, "normalized_url": "slot99.id", "status": "new"}])

            if request.method == "PATCH" and path == "/rest/v1/urls":
                return httpx.Response(200, json=[{"id": 1, **body}])

            if request.method == "POST" and path == "/rest/v1/rpc/claim_url_for_review":
                return httpx.Response(200, json=[{"id": 1, "locked_by": body["p_reviewer"]}])

            if request.method == "POST" and path == "/rest/v1/rpc/export_next_batch":
                return httpx.Response(
                    200,
                    json=[
                        {"batch_id": 7, "url_id": 1, "normalized_url": "slot99.id", "ai_category": "judol", "ai_note": "Promo slot"},
                        {"batch_id": 7, "url_id": 2, "normalized_url": "pinjol88.id", "ai_category": "pinjol", "ai_note": "Pinjaman ilegal"},
                    ],
                )

            if request.method == "POST" and path == "/rest/v1/rpc/status_counts":
                return httpx.Response(
                    200,
                    json=[
                        {"status": "new", "total": 12},
                        {"status": "approved", "total": 45},
                    ],
                )

            if request.method == "POST" and path.startswith("/storage/v1/object/screenshots/"):
                self.assertEqual(request.headers.get("content-type"), "image/jpeg")
                self.assertEqual(request.headers.get("x-upsert"), "true")
                return httpx.Response(200, json={"Key": path})

            raise AssertionError(f"Unexpected request: {request.method} {request.url}")

        client = httpx.Client(transport=httpx.MockTransport(handler))
        db = SupabaseDB("https://demo.supabase.co", "sb_secret_test", client=client)

        inserted = db.insert_urls(["https://www.Slot99.id/?utm=1", "slot99.id", "127.0.0.1"])
        self.assertEqual(len(inserted), 1)
        self.assertEqual(inserted[0]["normalized_url"], "slot99.id")
        self.assertEqual(inserted[0]["status"], "new")

        queue = db.fetch_queue()
        self.assertEqual(queue[0]["status"], "new")

        updated = db.update_status(1, status="triaged", ai_category="judol", reason_140="Situs slot gacor")
        self.assertEqual(updated["ai_note"], "Situs slot gacor")

        locked = db.lock_for_review("member-1")
        self.assertEqual(locked["locked_by"], "member-1")

        batch = db.export_next_batch("member-1", limit=20)
        self.assertEqual(batch["batch_id"], 7)
        self.assertEqual(batch["count"], 2)
        self.assertEqual(batch["text"], "slot99.id\npinjol88.id")

        obj_path = db.upload_screenshot("1_slot99.id.jpg", b"\xff\xd8\xffdemo")
        self.assertEqual(obj_path, "1_slot99.id.jpg")

        counts = db.get_status_counts()
        self.assertEqual(counts, {"new": 12, "approved": 45})


class TestScreenshotCompressionAndUpload(unittest.IsolatedAsyncioTestCase):
    def test_compress_jpeg_to_limit_enforces_150kb_ceiling(self):
        raw = _make_large_noisy_jpeg()
        self.assertGreater(len(raw), DEFAULT_MAX_SCREENSHOT_BYTES)

        compressed = compress_jpeg_to_limit(raw, max_bytes=DEFAULT_MAX_SCREENSHOT_BYTES, initial_quality=60)
        self.assertLessEqual(len(compressed), DEFAULT_MAX_SCREENSHOT_BYTES)
        # Verify compressed bytes are still a valid JPEG image
        with Image.open(BytesIO(compressed)) as img:
            self.assertEqual(img.format, "JPEG")

    async def test_verifier_compresses_and_auto_uploads_screenshot(self):
        raw = _make_large_noisy_jpeg()
        uploaded: list[tuple[str, int]] = []

        def fake_uploader(path: str, data: bytes) -> str:
            uploaded.append((path, len(data)))
            return path

        browser = _FakeBrowser(
            lambda u: {
                "final_url": "https://slotcontoh.id/daftar",
                "status": 200,
                "title": "Slot Contoh",
                "screenshot": raw,
            }
        )
        async with SafeBrowserVerifier(
            jpeg_quality=60,
            uploader=fake_uploader,
            playwright_factory=lambda: _FakePlaywrightCM(browser),
        ) as v:
            res = await v.verify_url("slotcontoh.id", url_id=42)

        self.assertEqual(res.status, "verified")
        self.assertEqual(res.screenshot_path, "42_slotcontoh.id_daftar.jpg")
        self.assertEqual(len(uploaded), 1)
        self.assertLessEqual(uploaded[0][1], DEFAULT_MAX_SCREENSHOT_BYTES)


class TestAITriage(unittest.TestCase):
    def test_triage_site_with_openai_sdk_client_normalizes_output(self):
        long_reason = "Situs judi slot gacor online ilegal " * 10
        fake_resp = SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(
                        content=json.dumps(
                            {
                                "category": "JUDOL",
                                "confidence": 1.4,
                                "reason_140": long_reason,
                            }
                        )
                    )
                )
            ]
        )

        called: dict = {}

        class _FakeCompletions:
            def create(self, **kwargs):
                called.update(kwargs)
                return fake_resp

        fake_client = SimpleNamespace(chat=SimpleNamespace(completions=_FakeCompletions()))
        res = triage_site(
            "slotgacor99.id",
            page_title="Slot Gacor 99",
            clean_text="Daftar slot deposit dana 10rb",
            client=fake_client,
            model="deepseek-chat",
            url_id=10,
        )

        self.assertEqual(called["model"], "deepseek-chat")
        self.assertEqual(called["response_format"], {"type": "json_object"})
        self.assertEqual(res.category, "judol")
        self.assertEqual(res.confidence, 1.0)
        self.assertLessEqual(len(res.reason_140), MAX_REASON_LEN)
        self.assertEqual(res.url_id, 10)

    def test_batch_prompt_export_30_per_prompt_and_webchat_import(self):
        sites = [
            {"id": i, "normalized_url": f"site{i}.id", "page_title": f"Site {i}", "clean_text": "slot gacor"}
            for i in range(1, 66)
        ]
        prompts = export_batch_prompts(sites, batch_size=DEFAULT_BATCH_SIZE)
        self.assertEqual(len(prompts), 3)  # 30 + 30 + 5

        with tempfile.TemporaryDirectory() as tmp:
            paths = write_batch_prompts(sites, Path(tmp))
            self.assertEqual([p.name for p in paths], ["deepseek_batch_001.txt", "deepseek_batch_002.txt", "deepseek_batch_003.txt"])

        web_reply = """Berikut hasil klasifikasinya:
```json
[
  {"id": 1, "normalized_url": "site1.id", "category": "judol", "confidence": 0.96, "reason_140": "Menawarkan permainan slot dan deposit e-wallet."},
  {"id": 2, "normalized_url": "site2.id", "category": "invalid_cat", "confidence": -0.5, "reason_140": "x"}
]
```
Semoga membantu!"""

        saved: list[tuple[int, dict]] = []

        class _FakeDB:
            def update_status(self, url_id: int, status: str, **fields):
                saved.append((url_id, {"status": status, **fields}))

        parsed = import_batch_response(web_reply, db=_FakeDB())
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0].category, "judol")
        self.assertEqual(parsed[1].category, "unsure")
        self.assertEqual(parsed[1].confidence, 0.0)
        self.assertEqual(len(saved), 2)
        self.assertEqual(saved[0][1]["status"], "triaged")
        self.assertEqual(len(parse_batch_response(web_reply)), 2)


class TestAppAtomicExport(unittest.TestCase):
    def test_concurrent_3_reviewers_export_next_20_no_overlap(self):
        from fastapi.testclient import TestClient
        from src.app import create_app

        class _AtomicMemoryDB:
            def __init__(self, total: int = 45):
                self._lock = threading.Lock()
                self._batch_seq = 0
                self.rows = [
                    {"id": i, "normalized_url": f"judol{i}.id", "status": "approved", "batch_id": None, "ai_category": "judol", "ai_note": "slot"}
                    for i in range(1, total + 1)
                ]
                self.batches: list[dict] = []

            def export_next_batch(self, reviewer: str, limit: int = 20) -> dict:
                with self._lock:
                    picked = [r for r in self.rows if r["status"] == "approved" and r["batch_id"] is None][:limit]
                    if not picked:
                        return {"batch_id": None, "reviewer": reviewer, "count": 0, "links": [], "text": "", "items": []}
                    self._batch_seq += 1
                    bid = self._batch_seq
                    self.batches.append({"id": bid, "reviewer": reviewer, "url_count": len(picked)})
                    for r in picked:
                        r["status"] = "exported"
                        r["batch_id"] = bid
                    links = [r["normalized_url"] for r in picked]
                    return {
                        "batch_id": bid,
                        "reviewer": reviewer,
                        "count": len(picked),
                        "links": links,
                        "text": "\n".join(links),
                        "items": [{"id": r["id"], "normalized_url": r["normalized_url"], "ai_category": r["ai_category"], "ai_note": r["ai_note"]} for r in picked],
                    }

        fake_db = _AtomicMemoryDB(total=45)
        client = TestClient(create_app(db=fake_db))

        def call_export(reviewer: str) -> dict:
            r = client.post("/api/export-next-20", json={"reviewer": reviewer})
            self.assertEqual(r.status_code, 200)
            return r.json()

        with ThreadPoolExecutor(max_workers=3) as pool:
            responses = list(pool.map(call_export, ["member-1", "member-2", "member-3"]))

        all_links = [link for resp in responses for link in resp["links"]]
        self.assertEqual(len(all_links), 45)
        self.assertEqual(len(set(all_links)), 45)  # Zero overlap across 3 concurrent reviewers
        self.assertEqual(sorted(resp["count"] for resp in responses), [5, 20, 20])
        self.assertEqual(len(fake_db.batches), 3)
        self.assertTrue(all(r["status"] == "exported" for r in fake_db.rows))

        # 4th call returns empty without creating an extra batch
        empty = call_export("member-1")
        self.assertIsNone(empty["batch_id"])
        self.assertEqual(empty["count"], 0)
        self.assertEqual(len(fake_db.batches), 3)

    def test_index_html_review_queue_and_anx_decisions(self):
        from fastapi.testclient import TestClient
        from src.app import create_app

        class _GalleryDB:
            def __init__(self):
                self.rows = {
                    1: {
                        "id": 1,
                        "normalized_url": "slot99.id",
                        "status": "triaged",
                        "page_title": "Slot 99",
                        "ai_category": "judol",
                        "ai_confidence": 0.96,
                        "ai_note": "Promo slot deposit dana",
                        "screenshot_path": "1_slot99.id.jpg",
                        "locked_by": None,
                    },
                    2: {
                        "id": 2,
                        "normalized_url": "pinjol88.id",
                        "status": "ai_scored",
                        "page_title": "Pinjol Cepat",
                        "ai_category": "pinjol",
                        "ai_confidence": 0.88,
                        "ai_note": "Pinjaman ilegal",
                        "screenshot_path": "2_pinjol88.id.jpg",
                        "locked_by": None,
                    },
                    3: {
                        "id": 3,
                        "normalized_url": "berita.id",
                        "status": "verified",
                        "page_title": "Portal Berita",
                        "ai_category": "benign",
                        "ai_confidence": 0.12,
                        "ai_note": "Situs berita normal",
                        "screenshot_path": None,
                        "locked_by": None,
                    },
                }

            def fetch_review_queue(self, statuses, limit=30):
                return [r for r in self.rows.values() if r["status"] in statuses][:limit]

            def get_status_counts(self):
                counts = {}
                for r in self.rows.values():
                    counts[r["status"]] = counts.get(r["status"], 0) + 1
                return counts

            def create_signed_url(self, path, expires_in=3600):
                return f"https://demo.supabase.co/storage/v1/object/sign/screenshots/{path}?token=abc"

            def update_status(self, url_id, status=None, **fields):
                if url_id not in self.rows:
                    return None
                if status is not None:
                    self.rows[url_id]["status"] = status
                self.rows[url_id].update(fields)
                return self.rows[url_id]

        db = _GalleryDB()
        client = TestClient(create_app(db=db))

        # 1. GET / serves separated templates/index.html with static CSS/JS & security headers
        html = client.get("/")
        self.assertEqual(html.status_code, 200)
        self.assertEqual(html.headers.get("x-content-type-options"), "nosniff")
        self.assertEqual(html.headers.get("x-frame-options"), "DENY")
        self.assertEqual(html.headers.get("referrer-policy"), "no-referrer")
        self.assertIn("Copy Next 20 Links", html.text)
        self.assertIn("Auto Pipeline", html.text)
        self.assertIn("Mulai Otomatis", html.text)
        self.assertIn('id="btnTheme"', html.text)
        self.assertIn('id="btnFilterIllegal"', html.text)
        self.assertIn("Ilegal Saja", html.text)
        self.assertIn('href="/static/styles.css?v=', html.text)
        self.assertIn('src="/static/app.js?v=', html.text)

        css = client.get("/static/styles.css")
        self.assertEqual(css.status_code, 200)
        self.assertIn('data-theme="light"', css.text)

        js = client.get("/static/app.js")
        self.assertEqual(js.status_code, 200)
        self.assertIn('key === "a"', js.text)
        self.assertIn('key === "n"', js.text)
        self.assertIn('key === "x"', js.text)

        # 2. GET /api/review/queue returns signed URLs & live counts
        q = client.get("/api/review/queue")
        self.assertEqual(q.status_code, 200)
        qdata = q.json()
        self.assertEqual(len(qdata["items"]), 3)
        self.assertIn("/object/sign/screenshots/1_slot99.id.jpg", qdata["items"][0]["screenshot_url"])
        self.assertEqual(qdata["counts"]["review_queue"], 3)

        # 3. A (approve), N (approve_note), X (skip)
        r_a = client.post("/api/review/1/decide", json={"reviewer": "member-1", "action": "approve"})
        self.assertEqual(r_a.status_code, 200)
        self.assertEqual(db.rows[1]["status"], "approved")

        r_n = client.post(
            "/api/review/2/decide",
            json={"reviewer": "member-2", "action": "approve_note", "note": "Pinjol ilegal tanpa izin OJK"},
        )
        self.assertEqual(r_n.status_code, 200)
        self.assertEqual(db.rows[2]["status"], "approved")
        self.assertEqual(db.rows[2]["ai_note"], "Pinjol ilegal tanpa izin OJK")

        r_x = client.post("/api/review/3/decide", json={"reviewer": "member-3", "action": "skip"})
        self.assertEqual(r_x.status_code, 200)
        self.assertEqual(db.rows[3]["status"], "skipped")

    def test_batch_history_and_mark_submitted_or_claimed_external(self):
        from fastapi.testclient import TestClient
        from src.app import create_app

        class _BatchHistoryDB:
            def __init__(self):
                self.batches = [{"id": 10, "reviewer": "member-1", "url_count": 2, "created_at": "2026-11-28T04:00:00Z"}]
                self.urls = {
                    101: {"id": 101, "batch_id": 10, "normalized_url": "slot1.id", "status": "exported"},
                    102: {"id": 102, "batch_id": 10, "normalized_url": "slot2.id", "status": "exported"},
                }

            def fetch_batches(self, limit=20):
                items = list(self.urls.values())
                links = [u["normalized_url"] for u in items]
                counts = {}
                for u in items:
                    counts[u["status"]] = counts.get(u["status"], 0) + 1
                return [{**self.batches[0], "items": items, "links": links, "text": "\n".join(links), "status_counts": counts}]

            def update_batch_urls_status(self, batch_id, status, reviewer=None):
                updated = []
                for u in self.urls.values():
                    if u["batch_id"] == batch_id:
                        u["status"] = status
                        updated.append(dict(u))
                return updated

            def update_status(self, url_id, status=None, **fields):
                if url_id not in self.urls:
                    return None
                if status is not None:
                    self.urls[url_id]["status"] = status
                self.urls[url_id].update(fields)
                return dict(self.urls[url_id])

        db = _BatchHistoryDB()
        client = TestClient(create_app(db=db))

        # 1. GET /api/batches returns batch history with links & status_counts
        res = client.get("/api/batches")
        self.assertEqual(res.status_code, 200)
        batches = res.json()["batches"]
        self.assertEqual(len(batches), 1)
        self.assertEqual(batches[0]["text"], "slot1.id\nslot2.id")
        self.assertEqual(batches[0]["status_counts"], {"exported": 2})

        # 2. Mark entire batch as submitted
        r_sub = client.post("/api/batches/10/status", json={"status": "submitted", "reviewer": "member-1"})
        self.assertEqual(r_sub.status_code, 200)
        self.assertEqual(r_sub.json()["updated_count"], 2)
        self.assertTrue(all(u["status"] == "submitted" for u in db.urls.values()))

        # 3. Mark one URL in the batch as claimed_external
        r_claim = client.post("/api/urls/102/status", json={"status": "claimed_external", "reviewer": "member-1"})
        self.assertEqual(r_claim.status_code, 200)
        self.assertEqual(db.urls[102]["status"], "claimed_external")
        self.assertEqual(client.get("/api/batches").json()["batches"][0]["status_counts"], {"submitted": 1, "claimed_external": 1})

    def test_ui_pipeline_endpoints_ingest_collect_verify_and_triage(self):
        from fastapi.testclient import TestClient
        from src.app import create_app
        from src.verify import VerifyResult

        class _PipelineDB:
            def __init__(self):
                self._seq = 0
                self.rows = {}

            def insert_urls(self, items, source="manual", status="new"):
                out = []
                seen = {r["normalized_url"] for r in self.rows.values()}
                for item in items:
                    raw = item if isinstance(item, str) else item["raw_url"]
                    norm = raw.replace("https://", "").replace("http://", "").strip("/")
                    if norm in seen or "127.0.0.1" in norm:
                        continue
                    seen.add(norm)
                    self._seq += 1
                    row = {
                        "id": self._seq,
                        "raw_url": raw,
                        "normalized_url": norm,
                        "source": source,
                        "status": status,
                        "ai_category": item.get("ai_category") if isinstance(item, dict) else None,
                        "ai_note": item.get("ai_note") if isinstance(item, dict) else None,
                    }
                    self.rows[self._seq] = row
                    out.append(row)
                return out

            def fetch_queue(self, status="new", limit=50):
                return [r for r in self.rows.values() if r["status"] == status][:limit]

            def update_status(self, url_id, status=None, **fields):
                row = self.rows.get(url_id)
                if not row:
                    return None
                if status is not None:
                    row["status"] = status
                row.update(fields)
                return row

            def upload_screenshot(self, path, data):
                return path

        class _FakeVerifier:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return None

            async def verify_url(self, raw_url, url_id=None):
                return VerifyResult(
                    input_url=raw_url,
                    normalized_url=raw_url.replace("https://", ""),
                    final_url=raw_url,
                    final_normalized_url=raw_url.replace("https://", ""),
                    status="verified",
                    http_status=200,
                    page_title="Slot Gacor 88",
                    raw_html="<html><body>Daftar slot online gacor</body></html>",
                    screenshot_bytes=b"\xff\xd8\xffdemo",
                    screenshot_path=f"{url_id}_slot.jpg",
                )

        async def _fake_collector(req):
            return [SimpleNamespace(normalized_url="auto-judol88.id", source="ct_log", category_hint="judol", matched_rule="judol:slot88")]

        db = _PipelineDB()
        client = TestClient(create_app(db=db, verifier_factory=_FakeVerifier, collector_fn=_fake_collector))

        # 1. Manual ingest
        r_ing = client.post("/api/pipeline/ingest", json={"urls_text": "https://manual1.id\nhttps://manual1.id\nhttp://127.0.0.1"})
        self.assertEqual(r_ing.status_code, 200)
        self.assertEqual(r_ing.json()["inserted_count"], 1)

        # 2. Automatic CT collector
        r_col = client.post("/api/pipeline/collect", json={"mode": "tail", "limit": 5})
        self.assertEqual(r_col.status_code, 200)
        self.assertEqual(r_col.json()["inserted_count"], 1)

        # 3. Verify queue -> screenshot path + verified
        r_ver = client.post("/api/pipeline/verify", json={"limit": 5})
        self.assertEqual(r_ver.status_code, 200)
        self.assertEqual(r_ver.json()["verified"], 2)

        # 4. Export batch prompt (30) + import DeepSeek web-chat reply
        r_exp = client.post("/api/pipeline/triage/export-prompts", json={"limit": 30})
        self.assertEqual(r_exp.status_code, 200)
        self.assertEqual(r_exp.json()["site_count"], 2)
        self.assertEqual(len(r_exp.json()["prompts"]), 1)

        reply = json.dumps([
            {"id": 1, "normalized_url": "manual1.id", "category": "judol", "confidence": 0.95, "reason_140": "Situs slot online"},
            {"id": 2, "normalized_url": "auto-judol88.id", "category": "judol", "confidence": 0.99, "reason_140": "Domain judol baru"},
        ])
        r_imp = client.post("/api/pipeline/triage/import", json={"raw_text": reply})
        self.assertEqual(r_imp.status_code, 200)
        self.assertEqual(r_imp.json()["imported_count"], 2)
        self.assertEqual(db.rows[1]["status"], "triaged")

        # 5. Re-verify approved keeps still-live URL as approved
        db.rows[1]["status"] = "approved"
        db.rows[1]["batch_id"] = None
        r_rev = client.post("/api/pipeline/reverify-approved", json={"limit": 10})
        self.assertEqual(r_rev.status_code, 200)
        self.assertEqual(r_rev.json()["still_approved"], 1)
        self.assertEqual(r_rev.json()["dead_or_blocked"], 0)
        self.assertEqual(db.rows[1]["status"], "approved")

    def test_mock_target_and_auto_submit_both_modes(self):
        from fastapi.testclient import TestClient
        from src.app import create_app
        from src.mock_target import create_mock_app
        from src.submitter import SubmitResult, detect_gate_or_captcha, validate_submit_target_url

        # 1. Mock portal accepts links, exposes /health, & detects duplicates
        mock_client = TestClient(create_mock_app())
        self.assertEqual(mock_client.get("/health").json(), {"status": "ok"})
        self.assertEqual(mock_client.get("/").status_code, 200)
        r1 = mock_client.post("/submit", content="reporter=tim1&links=https%3A%2F%2Fslot88.id%0Apinjol99.id", headers={"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(r1.status_code, 200)
        self.assertIn('data-submit-status="ok"', r1.text)
        r2 = mock_client.post("/submit", content="reporter=tim1&links=slot88.id%0Abaru77.id", headers={"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(r2.status_code, 200)
        sub_summary = mock_client.get("/api/submissions").json()
        self.assertEqual(sub_summary["total_submissions"], 2)
        self.assertEqual(sub_summary["submissions"][1]["duplicates"], ["slot88.id"])
        self.assertEqual(sub_summary["submissions"][1]["accepted"], ["baru77.id"])

        # 2. CAPTCHA & login detector flags Turnstile/reCAPTCHA/masuk without attempting bypass
        self.assertIsNotNone(detect_gate_or_captcha('<div class="cf-turnstile"></div>'))
        self.assertIsNotNone(
            detect_gate_or_captcha(
                '<form><input type="password" name="pw"></form>',
                current_url="https://imphnen.dev/masuk",
            )
        )
        self.assertIsNone(detect_gate_or_captcha('<form><textarea name="links"></textarea></form>'))

        # 2b. SSRF target URL allowlist validation
        self.assertEqual(validate_submit_target_url("http://127.0.0.1:8001"), "http://127.0.0.1:8001")
        self.assertEqual(validate_submit_target_url("http://mock-target:8001"), "http://mock-target:8001")
        self.assertEqual(validate_submit_target_url("https://imphnen.dev/hackaton-anti-judol"), "https://imphnen.dev/hackaton-anti-judol")
        with self.assertRaises(ValueError):
            validate_submit_target_url("http://169.254.169.254/latest/meta-data")
        with self.assertRaises(ValueError):
            validate_submit_target_url("file:///etc/passwd")
        with self.assertRaises(ValueError):
            validate_submit_target_url("https://evil.example.com/hook")

        # 3. Auto-submit endpoint supports BOTH review_first and full_auto modes
        class _SubmitDB:
            def __init__(self):
                self.batch_seq = 0
                self.rows = {
                    1: {"id": 1, "normalized_url": "approved1.id", "status": "approved", "batch_id": None, "ai_category": "judol", "ai_confidence": 0.95},
                    2: {"id": 2, "normalized_url": "ai-high.id", "status": "triaged", "batch_id": None, "ai_category": "judol", "ai_confidence": 0.92},
                    3: {"id": 3, "normalized_url": "ai-benign.id", "status": "triaged", "batch_id": None, "ai_category": "benign", "ai_confidence": 0.99},
                    4: {"id": 4, "normalized_url": "ai-lowconf.id", "status": "triaged", "batch_id": None, "ai_category": "scam", "ai_confidence": 0.40},
                    5: {"id": 5, "normalized_url": "untriaged-hint.id", "status": "verified", "batch_id": None, "ai_category": "judol", "ai_confidence": None},
                    6: {"id": 6, "normalized_url": "triaged-nullconf.id", "status": "triaged", "batch_id": None, "ai_category": "judol", "ai_confidence": None},
                }

            def fetch_review_queue(self, statuses, limit=30):
                return [r for r in self.rows.values() if r["status"] in statuses][:limit]

            def fetch_batch_by_id(self, batch_id):
                items = [r for r in self.rows.values() if r.get("batch_id") == batch_id]
                if not items:
                    return None
                links = [r.get("final_normalized_url") or r["normalized_url"] for r in items]
                return {"id": batch_id, "reviewer": "member-1", "items": items, "links": links, "text": "\n".join(links)}

            def update_status(self, url_id, status=None, **fields):
                row = self.rows[url_id]
                if status is not None:
                    row["status"] = status
                row.update(fields)
                return row

            def export_next_batch(self, reviewer, limit=20):
                picked = [r for r in self.rows.values() if r["status"] == "approved" and r["batch_id"] is None][:limit]
                if not picked:
                    return {"batch_id": None, "reviewer": reviewer, "count": 0, "links": [], "text": "", "items": []}
                self.batch_seq += 1
                bid = self.batch_seq
                for r in picked:
                    r["status"] = "exported"
                    r["batch_id"] = bid
                return {"batch_id": bid, "reviewer": reviewer, "count": len(picked), "links": [r["normalized_url"] for r in picked], "text": "\n".join(r["normalized_url"] for r in picked), "items": list(picked)}

            def update_batch_urls_status(self, batch_id, status, reviewer=None):
                out = []
                for r in self.rows.values():
                    if r["batch_id"] == batch_id:
                        r["status"] = status
                        out.append(r)
                return out

        async def _fake_submitter(links, reporter="member-1", target_url=None):
            return SubmitResult(ok=True, status="submitted", target_url=target_url or "http://127.0.0.1:8001", submitted_links=list(links), duplicate_links=[])

        db = _SubmitDB()
        client = TestClient(create_app(db=db, submitter_fn=_fake_submitter))

        # Mode A: review_first -> submits ONLY pre-approved row #1 (ignores triaged #2/#3/#4 & verified #5)
        res_a = client.post("/api/pipeline/auto-submit", json={"reviewer": "member-1", "mode": "review_first"})
        self.assertEqual(res_a.status_code, 200)
        self.assertEqual(res_a.json()["links"], ["approved1.id"])
        self.assertEqual(db.rows[1]["status"], "submitted")
        self.assertEqual(db.rows[2]["status"], "triaged")

        # Mode B: full_auto -> auto-promotes ONLY high-confidence triaged illegal row #2
        # Must NEVER promote benign #3, low-conf #4, un-triaged verified #5, or null-confidence #6
        res_b = client.post("/api/pipeline/auto-submit", json={"reviewer": "member-1", "mode": "full_auto", "min_confidence": 0.80})
        self.assertEqual(res_b.status_code, 200)
        self.assertEqual(res_b.json()["auto_approved"], 1)
        self.assertEqual(res_b.json()["links"], ["ai-high.id"])
        self.assertEqual(db.rows[2]["status"], "submitted")
        self.assertEqual(db.rows[3]["status"], "triaged")
        self.assertEqual(db.rows[4]["status"], "triaged")
        self.assertEqual(db.rows[5]["status"], "verified")
        self.assertEqual(db.rows[6]["status"], "triaged")

        # Mode C: SSRF override is rejected with HTTP 400 on both auto-submit endpoints
        res_ssrf_1 = client.post(
            "/api/pipeline/auto-submit",
            json={"reviewer": "member-1", "mode": "review_first", "target_url": "http://169.254.169.254/latest/meta-data"},
        )
        self.assertEqual(res_ssrf_1.status_code, 400)

        res_ssrf_2 = client.post(
            "/api/batches/1/auto-submit",
            json={"reviewer": "member-1", "target_url": "https://evil.example.com/hook"},
        )
        self.assertEqual(res_ssrf_2.status_code, 400)

        # Mode D: Re-submitting an existing batch via fetch_batch_by_id succeeds with allowed target
        res_batch = client.post("/api/batches/1/auto-submit", json={"reviewer": "member-1", "target_url": "http://127.0.0.1:8001"})
        self.assertEqual(res_batch.status_code, 200)
        self.assertEqual(res_batch.json()["submit"]["submitted_links"], ["approved1.id"])


if __name__ == "__main__":
    unittest.main()
