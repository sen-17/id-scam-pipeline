(() => {
  "use strict";

  const state = {
    items: [],
    batches: [],
    lastExportBatchId: null,
    selectedIndex: -1,
    filterMode: localStorage.getItem("gallery_filter") || "all",
    busy: false,
    autoLoop: false,
    autoRunning: false,
    autoCycle: 0,
    autoTimer: null,
  };

  const els = {
    workbench: document.getElementById("workbench"),
    gallery: document.getElementById("gallery"),
    reviewer: document.getElementById("reviewerInput"),
    cntNew: document.getElementById("cntNew"),
    cntNewInline: document.getElementById("cntNewInline"),
    cntVerifiedInline: document.getElementById("cntVerifiedInline"),
    cntQueue: document.getElementById("cntQueue"),
    cntApproved: document.getElementById("cntApproved"),
    cntExported: document.getElementById("cntExported"),
    cntSubmitted: document.getElementById("cntSubmitted"),
    cntClaimed: document.getElementById("cntClaimed"),
    cntSkipped: document.getElementById("cntSkipped"),
    autoDot: document.getElementById("autoDot"),
    autoSubmitMode: document.getElementById("autoSubmitMode"),
    autoInterval: document.getElementById("autoInterval"),
    autoIncludeAi: document.getElementById("autoIncludeAi"),
    btnAutoOnce: document.getElementById("btnAutoOnce"),
    btnAutoLoop: document.getElementById("btnAutoLoop"),
    btnAutoSubmitNow: document.getElementById("btnAutoSubmitNow"),
    statusAuto: document.getElementById("statusAuto"),
    collectMode: document.getElementById("collectMode"),
    collectLimit: document.getElementById("collectLimit"),
    collectDuration: document.getElementById("collectDuration"),
    statusCollect: document.getElementById("statusCollect"),
    ingestInput: document.getElementById("ingestInput"),
    statusIngest: document.getElementById("statusIngest"),
    verifyLimit: document.getElementById("verifyLimit"),
    statusVerify: document.getElementById("statusVerify"),
    triageImportInput: document.getElementById("triageImportInput"),
    statusTriage: document.getElementById("statusTriage"),
    batchesList: document.getElementById("batchesList"),
    batchTotalLabel: document.getElementById("batchTotalLabel"),
    inspEmpty: document.getElementById("inspectorEmpty"),
    inspContent: document.getElementById("inspectorContent"),
    inspImg: document.getElementById("inspImg"),
    inspIdStatus: document.getElementById("inspIdStatus"),
    inspUrl: document.getElementById("inspUrl"),
    inspFinalUrl: document.getElementById("inspFinalUrl"),
    inspTitle: document.getElementById("inspTitle"),
    inspAi: document.getElementById("inspAi"),
    inspLock: document.getElementById("inspLock"),
    inspSnippet: document.getElementById("inspSnippet"),
    noteInput: document.getElementById("noteInput"),
    noteCounter: document.getElementById("noteCounter"),
    exportModal: document.getElementById("exportModal"),
    exportTitle: document.getElementById("exportTitle"),
    exportTextarea: document.getElementById("exportTextarea"),
    zoomModal: document.getElementById("zoomModal"),
    zoomImg: document.getElementById("zoomImg"),
    toast: document.getElementById("toast"),
    filterSummary: document.getElementById("filterSummary"),
    btnFilterAll: document.getElementById("btnFilterAll"),
    btnFilterIllegal: document.getElementById("btnFilterIllegal"),
  };

  /* Helpers */
  const savedReviewer = localStorage.getItem("reviewer_name");
  if (savedReviewer) els.reviewer.value = savedReviewer;
  els.reviewer.addEventListener("change", () => {
    localStorage.setItem("reviewer_name", getReviewer());
  });

  function getReviewer() {
    return (els.reviewer.value || "").trim() || "member-1";
  }

  let toastTimer = null;
  function showToast(msg) {
    els.toast.textContent = msg;
    els.toast.style.display = "block";
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { els.toast.style.display = "none"; }, 3200);
  }

  function escapeHtml(str) {
    return String(str ?? "").replace(/[&<>"']/g, (ch) => (
      { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]
    ));
  }

  function categoryClass(cat) {
    const c = String(cat || "unsure").toLowerCase();
    return `cat-${c.replace(/[^a-z]/g, "") || "unsure"}`;
  }

  function formatConfidence(val) {
    if (val === null || val === undefined || Number.isNaN(Number(val))) return "-";
    return `${Math.round(Number(val) * 100)}%`;
  }

  function formatTime(iso) {
    if (!iso) return "-";
    const d = new Date(iso);
    return Number.isNaN(d.getTime())
      ? String(iso)
      : d.toLocaleString("id-ID", { dateStyle: "short", timeStyle: "short" });
  }

  function updateNoteCounter() {
    els.noteCounter.textContent = `${els.noteInput.value.length}/140`;
  }
  els.noteInput.addEventListener("input", updateNoteCounter);

  function visibleItems() {
    if (state.filterMode !== "illegal") return state.items;
    return state.items.filter((item) => {
      const cat = String(item.ai_category || "").toLowerCase();
      return cat !== "benign" && cat !== "legit";
    });
  }

  function currentItem() {
    const list = visibleItems();
    return list[state.selectedIndex] || null;
  }

  async function copyText(text) {
    if (!text) return false;
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
        return true;
      }
    } catch (_) {}
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand("copy");
    document.body.removeChild(ta);
    return ok;
  }

  async function postJson(url, body) {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await res.json().catch(() => ({}));
    return { res, data };
  }

  /* Counters & Auto Pipeline */
  function renderCounts(counts = {}) {
    els.cntNew.textContent = counts.new ?? 0;
    els.cntNewInline.textContent = counts.new ?? 0;
    els.cntVerifiedInline.textContent = counts.verified ?? 0;
    els.cntQueue.textContent = counts.review_queue ?? state.items.length;
    els.cntApproved.textContent = counts.approved ?? 0;
    els.cntExported.textContent = counts.exported ?? 0;
    els.cntSubmitted.textContent = counts.submitted ?? 0;
    els.cntClaimed.textContent = counts.claimed_external ?? 0;
    els.cntSkipped.textContent = counts.skipped ?? 0;
  }

  function updateAutoUi() {
    const active = state.autoLoop || state.autoRunning;
    els.autoDot.classList.toggle("running", active);
    els.btnAutoOnce.disabled = state.autoRunning;
    if (state.autoLoop) {
      els.btnAutoLoop.textContent = "Stop Otomatis";
      els.btnAutoLoop.className = "btn-danger";
    } else {
      els.btnAutoLoop.textContent = "Mulai Otomatis";
      els.btnAutoLoop.className = "btn-approve";
    }
  }

  async function runAutoCycle() {
    if (state.autoRunning) return;
    state.autoRunning = true;
    state.autoCycle += 1;
    const cycle = state.autoCycle;
    updateAutoUi();

    try {
      els.statusAuto.textContent = `#${cycle} · Mencari domain (${els.collectMode.value})...`;
      const { res: colRes, data: colData } = await postJson("/api/pipeline/collect", {
        mode: els.collectMode.value,
        limit: Number(els.collectLimit.value) || 10,
        duration: Number(els.collectDuration.value) || 15,
      });
      if (!colRes.ok) throw new Error(`Collect: ${colData.detail || colRes.status}`);
      els.statusCollect.textContent = `+${colData.inserted_count} baru (${colData.found_count} ketemu)`;

      els.statusAuto.textContent = `#${cycle} · Verifikasi & screenshot (+${colData.inserted_count} baru)...`;
      const { res: verRes, data: verData } = await postJson("/api/pipeline/verify", {
        limit: Number(els.verifyLimit.value) || 5,
        concurrency: 3,
      });
      if (!verRes.ok) throw new Error(`Verify: ${verData.detail || verRes.status}`);
      els.statusVerify.textContent = `${verData.verified} hidup · ${verData.dead_or_blocked} mati`;

      let aiSummary = "AI skip";
      if (els.autoIncludeAi.checked) {
        els.statusAuto.textContent = `#${cycle} · AI Triage...`;
        const { res: aiRes, data: aiData } = await postJson("/api/pipeline/triage/api", { limit: 10 });
        if (aiRes.ok) {
          aiSummary = `AI ${aiData.triaged_count}`;
        } else if (aiRes.status === 400) {
          aiSummary = "AI key kosong";
          els.autoIncludeAi.checked = false;
        } else {
          aiSummary = `AI err ${aiRes.status}`;
        }
      }

      let submitSummary = "Review dulu";
      if (els.autoSubmitMode.value === "full_auto") {
        els.statusAuto.textContent = `#${cycle} · Auto Submit ke portal target...`;
        const { res: subRes, data: subData } = await postJson("/api/pipeline/auto-submit", {
          reviewer: getReviewer(),
          mode: "full_auto",
          limit: 20,
        });
        if (subRes.ok && subData.submit && subData.submit.ok) {
          submitSummary = `Submit #${subData.batch_id} (${subData.count})`;
        } else if (subRes.ok && !subData.count) {
          submitSummary = "Submit 0";
        } else {
          submitSummary = `Submit: ${(subData.submit && subData.submit.detail) || subData.detail || subRes.status}`;
        }
      }

      await Promise.all([loadQueue(), loadBatches()]);
      els.statusAuto.textContent = `#${cycle} selesai · +${colData.inserted_count} URL · ${verData.verified} capture · ${aiSummary} · ${submitSummary}`;
      showToast(`Auto #${cycle}: +${colData.inserted_count} URL, ${verData.verified} capture, ${submitSummary}.`);
    } catch (err) {
      els.statusAuto.textContent = `#${cycle} error: ${err.message}`;
      showToast(`Auto pipeline error: ${err.message}`);
    } finally {
      state.autoRunning = false;
      updateAutoUi();
      if (state.autoLoop) scheduleNextAutoCycle();
    }
  }

  function scheduleNextAutoCycle() {
    clearTimeout(state.autoTimer);
    let left = Math.max(10, Number(els.autoInterval.value) || 30);
    const tick = () => {
      if (!state.autoLoop) return;
      if (left <= 0) {
        runAutoCycle();
        return;
      }
      els.statusAuto.textContent = `Loop aktif · siklus berikutnya ${left}s`;
      left -= 1;
      state.autoTimer = setTimeout(tick, 1000);
    };
    tick();
  }

  function toggleAutoLoop() {
    if (state.autoLoop) {
      state.autoLoop = false;
      clearTimeout(state.autoTimer);
      els.statusAuto.textContent = "Dihentikan";
      showToast("Mode otomatis dihentikan.");
      updateAutoUi();
    } else {
      state.autoLoop = true;
      updateAutoUi();
      showToast("Mode otomatis dimulai.");
      runAutoCycle();
    }
  }

  /* Manual Workbench Actions */
  async function runCollect() {
    const btn = document.getElementById("btnCollect");
    btn.disabled = true;
    els.statusCollect.textContent = "Memindai CT log...";
    try {
      const { res, data } = await postJson("/api/pipeline/collect", {
        mode: els.collectMode.value,
        limit: Number(els.collectLimit.value) || 10,
        duration: Number(els.collectDuration.value) || 15,
      });
      if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
      els.statusCollect.textContent = `+${data.inserted_count} baru (${data.found_count} kandidat)`;
      showToast(`CT Discovery: +${data.inserted_count} URL baru.`);
      await loadQueue();
    } catch (err) {
      els.statusCollect.textContent = err.message;
      showToast(`Collector gagal: ${err.message}`);
    } finally {
      btn.disabled = false;
    }
  }

  async function runIngest() {
    const text = els.ingestInput.value.trim();
    if (!text) {
      showToast("Tempel minimal 1 URL dulu.");
      return;
    }
    const btn = document.getElementById("btnIngest");
    btn.disabled = true;
    els.statusIngest.textContent = "Menyimpan...";
    try {
      const { res, data } = await postJson("/api/pipeline/ingest", {
        urls_text: text,
        source: "manual_ui",
      });
      if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
      els.ingestInput.value = "";
      els.statusIngest.textContent = `+${data.inserted_count} baru (${data.skipped_or_dup} skip/dup)`;
      showToast(`+${data.inserted_count} URL masuk antrean.`);
      await loadQueue();
    } catch (err) {
      els.statusIngest.textContent = err.message;
      showToast(`Ingest gagal: ${err.message}`);
    } finally {
      btn.disabled = false;
    }
  }

  async function runVerifyQueue() {
    const btn = document.getElementById("btnVerify");
    btn.disabled = true;
    els.statusVerify.textContent = "Capturing screenshot...";
    try {
      const { res, data } = await postJson("/api/pipeline/verify", {
        limit: Number(els.verifyLimit.value) || 5,
        concurrency: 3,
      });
      if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
      els.statusVerify.textContent = `${data.verified} hidup · ${data.dead_or_blocked} mati`;
      showToast(`Capture selesai: ${data.verified} siap direview.`);
      await loadQueue();
    } catch (err) {
      els.statusVerify.textContent = err.message;
      showToast(`Verifikasi gagal: ${err.message}`);
    } finally {
      btn.disabled = false;
    }
  }

  async function runReverifyApproved() {
    const btn = document.getElementById("btnReverifyApproved");
    const limit = Math.max(1, Math.min(20, Number(els.verifyLimit.value) || 5));
    btn.disabled = true;
    els.statusVerify.textContent = `Cek ulang ${limit} Approved terlama...`;
    showToast(`Mengecek ulang ${limit} link Approved terlama...`);
    try {
      const { res, data } = await postJson("/api/pipeline/reverify-approved", {
        limit,
        concurrency: 4,
        timeout_ms: 9000,
      });
      if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
      if (!data.processed) {
        els.statusVerify.textContent = "Belum ada link Approved";
        showToast("Belum ada link berstatus Approved untuk dicek ulang.");
        return;
      }
      els.statusVerify.textContent = `${data.still_approved} masih hidup · ${data.dead_or_blocked} gugur`;
      showToast(`Cek ulang Approved: ${data.still_approved} hidup, ${data.dead_or_blocked} mati/Trust+.`);
      await loadQueue();
    } catch (err) {
      els.statusVerify.textContent = err.message;
      showToast(`Cek ulang gagal: ${err.message}`);
    } finally {
      btn.disabled = false;
    }
  }

  async function runTriageApi() {
    const btn = document.getElementById("btnTriageApi");
    btn.disabled = true;
    els.statusTriage.textContent = "Memanggil AI API...";
    try {
      const { res, data } = await postJson("/api/pipeline/triage/api", { limit: 10 });
      if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
      els.statusTriage.textContent = `${data.triaged_count} situs dinilai`;
      showToast(`AI API: ${data.triaged_count} situs.`);
      await loadQueue();
    } catch (err) {
      els.statusTriage.textContent = err.message;
      showToast(`AI API: ${err.message}`);
    } finally {
      btn.disabled = false;
    }
  }

  async function runTriageExportPrompts() {
    try {
      const { res, data } = await postJson("/api/pipeline/triage/export-prompts", {
        limit: 30,
        batch_size: 30,
      });
      if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
      if (!data.prompts || !data.prompts.length) {
        els.statusTriage.textContent = "Antrean verified kosong";
        showToast("Belum ada situs verified.");
        return;
      }
      await copyText(data.prompts[0]);
      els.statusTriage.textContent = `Prompt ${data.site_count} situs disalin`;
      showToast(`Prompt ${data.site_count} situs tersalin ke clipboard.`);
    } catch (err) {
      showToast(`Export prompt gagal: ${err.message}`);
    }
  }

  async function runTriageImport() {
    const raw = els.triageImportInput.value.trim();
    if (!raw) {
      showToast("Paste balasan JSON AI dulu.");
      return;
    }
    const btn = document.getElementById("btnTriageImport");
    btn.disabled = true;
    try {
      const { res, data } = await postJson("/api/pipeline/triage/import", { raw_text: raw });
      if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
      els.triageImportInput.value = "";
      els.statusTriage.textContent = `${data.imported_count} hasil AI masuk`;
      showToast(`Imported ${data.imported_count} hasil AI.`);
      await loadQueue();
    } catch (err) {
      els.statusTriage.textContent = err.message;
      showToast(`Import gagal: ${err.message}`);
    } finally {
      btn.disabled = false;
    }
  }

  /* Batch History & Status Updates */
  function renderBatches() {
    els.batchTotalLabel.textContent = `${state.batches.length} batch`;
    if (!state.batches.length) {
      els.batchesList.innerHTML = `<div style="padding:20px;text-align:center;color:var(--ink-3);font-size:12px;">Belum ada riwayat batch export.</div>`;
      return;
    }

    els.batchesList.innerHTML = state.batches.map((b) => {
      const sc = b.status_counts || {};
      const badges = Object.entries(sc)
        .map(([st, cnt]) => `<span class="st-pill st-${escapeHtml(st)}">${escapeHtml(st)} ${cnt}</span>`)
        .join("");
      const itemRows = (b.items || []).map((u) => `
        <div class="batch-item-row">
          <div style="display:flex;align-items:center;gap:8px;min-width:0;">
            <span class="url-text">${escapeHtml(u.normalized_url)}</span>
            <span class="st-pill st-${escapeHtml(u.status)}">${escapeHtml(u.status)}</span>
          </div>
          <div style="display:flex;gap:4px;">
            <button type="button" class="btn-ghost" data-url-id="${u.id}" data-url-status="submitted">Submitted</button>
            <button type="button" class="btn-ghost" data-url-id="${u.id}" data-url-status="claimed_external">Claimed</button>
          </div>
        </div>
      `).join("");

      return `
        <div class="batch-row" data-batch-id="${b.id}">
          <div class="batch-top">
            <div class="batch-meta">
              <strong class="mono">#${b.id}</strong>
              <span style="color:var(--ink-2);">@${escapeHtml(b.reviewer)}</span>
              <span class="tabular" style="color:var(--ink-3);">${b.url_count} link</span>
              <span class="tabular" style="color:var(--ink-3);font-size:11.5px;">${escapeHtml(formatTime(b.created_at))}</span>
              ${badges}
            </div>
            <div class="batch-actions">
              <button type="button" class="btn-outline" data-batch-copy="${b.id}">Copy</button>
              <button type="button" class="btn-outline" data-batch-autosubmit="${b.id}" title="Kirim batch ini ke portal target via Playwright">Auto Submit</button>
              <button type="button" class="btn-approve" data-batch-status="submitted" data-batch-id="${b.id}">Tandai Submitted</button>
              <button type="button" class="btn-warn" data-batch-status="claimed_external" data-batch-id="${b.id}">Claimed External</button>
            </div>
          </div>
          <details>
            <summary class="details-summary">Lihat ${(b.items || []).length} link</summary>
            <div class="batch-items">${itemRows || '<span style="color:var(--ink-3);font-size:11.5px;">(Kosong)</span>'}</div>
          </details>
        </div>
      `;
    }).join("");
  }

  async function loadBatches() {
    try {
      const res = await fetch("/api/batches?limit=20");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      state.batches = data.batches || [];
      renderBatches();
    } catch (err) {
      showToast(`Gagal memuat riwayat batch: ${err.message}`);
    }
  }

  async function markBatchStatus(batchId, status) {
    try {
      const { res, data } = await postJson(`/api/batches/${batchId}/status`, {
        status,
        reviewer: getReviewer(),
      });
      if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
      showToast(`Batch #${batchId} (${data.updated_count} link) -> ${status}.`);
      await Promise.all([loadQueue(), loadBatches()]);
    } catch (err) {
      showToast(`Gagal update batch: ${err.message}`);
    }
  }

  async function markUrlStatus(urlId, status) {
    try {
      const { res, data } = await postJson(`/api/urls/${urlId}/status`, {
        status,
        reviewer: getReviewer(),
      });
      if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
      showToast(`URL #${urlId} -> ${status}.`);
      await Promise.all([loadQueue(), loadBatches()]);
    } catch (err) {
      showToast(`Gagal update URL: ${err.message}`);
    }
  }

  /* Review Gallery & Inspector */
  function syncFilterUi() {
    if (els.btnFilterAll) els.btnFilterAll.classList.toggle("active", state.filterMode === "all");
    if (els.btnFilterIllegal) els.btnFilterIllegal.classList.toggle("active", state.filterMode === "illegal");
    if (els.filterSummary) {
      const shown = visibleItems().length;
      const hidden = Math.max(0, state.items.length - shown);
      els.filterSummary.textContent = hidden > 0 ? `${shown} tampil · ${hidden} benign disembunyikan` : "";
    }
  }

  function renderGallery() {
    syncFilterUi();
    const list = visibleItems();
    if (!list.length) {
      const msg = state.items.length
        ? `Semua ${state.items.length} situs saat ini berkategori benign. Klik <strong>Semua</strong> untuk menampilkannya.`
        : `Antrean review kosong. Jalankan <strong>Auto Pipeline</strong> atau <strong>Browser Capture</strong> di atas.`;
      els.gallery.innerHTML = `<div class="empty-state">${msg}</div>`;
      renderInspector();
      return;
    }

    const me = getReviewer();
    els.gallery.innerHTML = list.map((item, idx) => {
      const active = idx === state.selectedIndex ? "active" : "";
      const lockedOther = item.locked_by && item.locked_by !== me ? "locked-other" : "";
      const cat = item.ai_category || "unsure";
      const confPct = item.ai_confidence != null ? Math.round(Number(item.ai_confidence) * 100) : 0;
      const shot = item.screenshot_url
        ? `<img src="${escapeHtml(item.screenshot_url)}" alt="${escapeHtml(item.normalized_url)}" loading="lazy" />`
        : `<span class="no-shot">Tanpa screenshot</span>`;
      const lockBadge = item.locked_by
        ? `<span class="tag lock-tag">@${escapeHtml(item.locked_by)}</span>`
        : "";

      return `
        <article class="card ${active} ${lockedOther}" data-idx="${idx}">
          <div class="thumb-wrap">
            ${shot}
            <div class="thumb-overlay">
              <span class="tag ${categoryClass(cat)}"><span class="tag-dot"></span>${escapeHtml(cat)} <span class="tabular">${formatConfidence(item.ai_confidence)}</span></span>
              ${lockBadge}
            </div>
          </div>
          <div class="card-body">
            <div class="url-text">${escapeHtml(item.normalized_url)}</div>
            <div class="title-text">${escapeHtml(item.page_title || "Tanpa judul")}</div>
            <div class="conf-track"><div class="conf-fill" style="width:${Math.min(100, Math.max(0, confPct))}%"></div></div>
            <div class="ai-note">${escapeHtml(item.ai_note || "Belum ada catatan AI")}</div>
            <div class="card-actions">
              <button type="button" data-act="approve" data-idx="${idx}"><span class="kbd">A</span>OK</button>
              <button type="button" data-act="approve_note" data-idx="${idx}"><span class="kbd">N</span>Note</button>
              <button type="button" data-act="skip" data-idx="${idx}"><span class="kbd">X</span>Skip</button>
            </div>
          </div>
        </article>
      `;
    }).join("");

    const activeEl = els.gallery.querySelector(".card.active");
    if (activeEl) activeEl.scrollIntoView({ block: "nearest", behavior: "smooth" });
    renderInspector();
  }

  function renderInspector() {
    const item = currentItem();
    if (!item) {
      els.inspEmpty.style.display = "block";
      els.inspContent.style.display = "none";
      return;
    }
    els.inspEmpty.style.display = "none";
    els.inspContent.style.display = "flex";

    if (item.screenshot_url) {
      els.inspImg.src = item.screenshot_url;
      els.inspImg.style.display = "block";
    } else {
      els.inspImg.removeAttribute("src");
      els.inspImg.style.display = "none";
    }

    els.inspIdStatus.textContent = `#${item.id} · ${item.status} · HTTP ${item.http_status ?? "-"}`;
    els.inspUrl.textContent = item.normalized_url || "-";
    els.inspFinalUrl.textContent = item.final_normalized_url || item.normalized_url || "-";
    els.inspTitle.textContent = item.page_title || "-";
    els.inspAi.innerHTML = `<span class="tag ${categoryClass(item.ai_category)}"><span class="tag-dot"></span>${escapeHtml(item.ai_category || "unsure")} ${formatConfidence(item.ai_confidence)}</span>`;
    els.inspLock.textContent = item.locked_by ? `@${item.locked_by}` : "Terbuka";
    els.noteInput.value = (item.ai_note || "").slice(0, 140);
    updateNoteCounter();
    els.inspSnippet.textContent = item.clean_text || "(Tidak ada teks terekstrak)";
  }

  async function lockCard(idx) {
    const list = visibleItems();
    const item = list[idx];
    if (!item) return;
    try {
      const { res, data } = await postJson("/api/review/lock", {
        reviewer: getReviewer(),
        url_id: item.id,
      });
      if (res.status === 409) {
        showToast(`#${item.id} sedang dikunci reviewer lain.`);
        return;
      }
      if (res.ok && data.locked) {
        const masterIdx = state.items.findIndex((r) => r.id === item.id);
        if (masterIdx !== -1) state.items[masterIdx] = { ...item, ...data.locked };
        renderGallery();
      }
    } catch (err) {
      console.warn("Lock failed:", err);
    }
  }

  async function selectIndex(idx, shouldLock = true) {
    const list = visibleItems();
    if (!list.length) {
      state.selectedIndex = -1;
      renderGallery();
      return;
    }
    state.selectedIndex = Math.max(0, Math.min(idx, list.length - 1));
    renderGallery();
    if (shouldLock) await lockCard(state.selectedIndex);
  }

  async function loadQueue() {
    try {
      const res = await fetch("/api/review/queue?limit=40");
      if (res.status === 404 || res.status === 405) {
        throw new Error("Backend FastAPI belum aktif. Jalankan `docker compose up dashboard` lalu buka http://127.0.0.1:8000 (jangan pakai Live Server).");
      }
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      state.items = data.items || [];
      renderCounts(data.counts);
      const list = visibleItems();
      await selectIndex(list.length ? 0 : -1, list.length > 0);
    } catch (err) {
      showToast(`Gagal memuat antrean: ${err.message}`);
    }
  }

  async function submitDecision(action, customNote = null) {
    const item = currentItem();
    if (!item || state.busy) return;
    state.busy = true;
    try {
      const payload = { reviewer: getReviewer(), action };
      if (action === "approve_note") {
        payload.note = (customNote !== null ? customNote : els.noteInput.value).trim().slice(0, 140);
      }
      const { res, data } = await postJson(`/api/review/${item.id}/decide`, payload);
      if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
      const label = action === "skip" ? "Skipped" : (action === "approve_note" ? "Approved + Note" : "Approved");
      showToast(`${label}: ${item.normalized_url}`);

      const masterIdx = state.items.findIndex((r) => r.id === item.id);
      if (masterIdx !== -1) state.items.splice(masterIdx, 1);
      els.cntQueue.textContent = String(Math.max(0, Number(els.cntQueue.textContent) - 1));
      if (action === "skip") {
        els.cntSkipped.textContent = String(Number(els.cntSkipped.textContent) + 1);
      } else {
        els.cntApproved.textContent = String(Number(els.cntApproved.textContent) + 1);
      }
      els.noteInput.blur();
      const nextList = visibleItems();
      await selectIndex(Math.min(state.selectedIndex, nextList.length - 1), nextList.length > 0);
    } catch (err) {
      showToast(`Gagal menyimpan: ${err.message}`);
    } finally {
      state.busy = false;
    }
  }

  /* Export & Auto-Submit */
  async function exportNext20() {
    try {
      const { res, data } = await postJson("/api/export-next-20", {
        reviewer: getReviewer(),
        limit: 20,
      });
      if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
      if (!data.count) {
        showToast("Belum ada link berstatus approved untuk di-export.");
        return;
      }
      state.lastExportBatchId = data.batch_id;
      els.exportTitle.textContent = `Batch #${data.batch_id} · ${data.count} link (@${data.reviewer})`;
      els.exportTextarea.value = data.text;
      els.exportModal.classList.add("open");
      const copied = await copyText(data.text);
      showToast(
        copied
          ? `Batch #${data.batch_id} (${data.count} link) disalin ke clipboard.`
          : `Batch #${data.batch_id} siap disalin.`
      );
      await Promise.all([loadQueue(), loadBatches()]);
    } catch (err) {
      showToast(`Export gagal: ${err.message}`);
    }
  }

  async function runAutoSubmitNow() {
    const mode = els.autoSubmitMode.value;
    els.btnAutoSubmitNow.disabled = true;
    els.statusAuto.textContent = `Auto Submit (${mode}) ke portal target...`;
    try {
      const { res, data } = await postJson("/api/pipeline/auto-submit", {
        reviewer: getReviewer(),
        mode,
        limit: 20,
      });
      if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
      if (!data.count) {
        const msg = mode === "review_first"
          ? "Belum ada link Approved (approve dulu dengan A/N, atau pilih mode Auto Submit AI)."
          : "Belum ada link AI ilegal siap auto-submit.";
        els.statusAuto.textContent = msg;
        showToast(msg);
        return;
      }
      const sub = data.submit || {};
      if (sub.ok) {
        const dupCount = (sub.duplicate_links || []).length;
        els.statusAuto.textContent = `Batch #${data.batch_id} terkirim (${data.count} link, ${dupCount} dup).`;
        showToast(`Batch #${data.batch_id} berhasil di-submit ke portal target!`);
      } else {
        els.statusAuto.textContent = `Batch #${data.batch_id} tertahan: ${sub.detail || "gagal"} (tersimpan di Riwayat Batch).`;
        showToast(`Auto Submit tertahan: ${sub.detail || "cek Riwayat Batch"}.`);
      }
      await Promise.all([loadQueue(), loadBatches()]);
    } catch (err) {
      els.statusAuto.textContent = `Auto Submit error: ${err.message}`;
      showToast(`Auto Submit gagal: ${err.message}`);
    } finally {
      els.btnAutoSubmitNow.disabled = false;
    }
  }

  async function autoSubmitBatchById(batchId) {
    showToast(`Mengirim Batch #${batchId} ke portal target...`);
    try {
      const { res, data } = await postJson(`/api/batches/${batchId}/auto-submit`, {
        reviewer: getReviewer(),
      });
      if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
      const sub = data.submit || {};
      showToast(sub.ok ? `Batch #${batchId} terkirim ke portal target!` : `Batch #${batchId}: ${sub.detail || "gagal"}`);
      await Promise.all([loadQueue(), loadBatches()]);
    } catch (err) {
      showToast(`Auto Submit Batch #${batchId} gagal: ${err.message}`);
    }
  }

  /* Event Delegation & Keyboard Shortcuts */
  els.batchesList.addEventListener("click", async (ev) => {
    const copyBtn = ev.target.closest("button[data-batch-copy]");
    if (copyBtn) {
      const bid = Number(copyBtn.dataset.batchCopy);
      const batch = state.batches.find((b) => Number(b.id) === bid);
      if (batch && batch.text) {
        await copyText(batch.text);
        showToast(`Batch #${bid} (${batch.links.length} link) disalin.`);
      }
      return;
    }
    const autoSubBtn = ev.target.closest("button[data-batch-autosubmit]");
    if (autoSubBtn) {
      await autoSubmitBatchById(Number(autoSubBtn.dataset.batchAutosubmit));
      return;
    }
    const batchStatusBtn = ev.target.closest("button[data-batch-status]");
    if (batchStatusBtn) {
      await markBatchStatus(Number(batchStatusBtn.dataset.batchId), batchStatusBtn.dataset.batchStatus);
      return;
    }
    const urlStatusBtn = ev.target.closest("button[data-url-id]");
    if (urlStatusBtn) {
      await markUrlStatus(Number(urlStatusBtn.dataset.urlId), urlStatusBtn.dataset.urlStatus);
    }
  });

  els.gallery.addEventListener("click", async (ev) => {
    const btn = ev.target.closest("button[data-act]");
    if (btn) {
      ev.stopPropagation();
      const idx = Number(btn.dataset.idx);
      const act = btn.dataset.act;
      if (idx !== state.selectedIndex) await selectIndex(idx, false);
      if (act === "approve_note") {
        els.noteInput.focus();
        els.noteInput.select();
      } else {
        await submitDecision(act);
      }
      return;
    }
    const card = ev.target.closest(".card[data-idx]");
    if (card) await selectIndex(Number(card.dataset.idx), true);
  });

  const btnTheme = document.getElementById("btnTheme");
  function syncThemeButton() {
    const isLight = document.documentElement.dataset.theme === "light";
    btnTheme.textContent = isLight ? "Dark" : "Light";
  }
  syncThemeButton();
  btnTheme.addEventListener("click", () => {
    const next = document.documentElement.dataset.theme === "light" ? "dark" : "light";
    document.documentElement.dataset.theme = next;
    localStorage.setItem("theme", next);
    syncThemeButton();
  });

  const btnToggleWorkbench = document.getElementById("btnToggleWorkbench");
  btnToggleWorkbench.addEventListener("click", () => {
    const collapsed = els.workbench.classList.toggle("collapsed");
    btnToggleWorkbench.setAttribute("aria-expanded", String(!collapsed));
    btnToggleWorkbench.textContent = collapsed ? "Alat Manual +" : "Tutup Alat -";
  });
  els.btnAutoOnce.addEventListener("click", runAutoCycle);
  els.btnAutoLoop.addEventListener("click", toggleAutoLoop);
  els.btnAutoSubmitNow.addEventListener("click", runAutoSubmitNow);
  document.getElementById("btnCollect").addEventListener("click", runCollect);
  document.getElementById("btnIngest").addEventListener("click", runIngest);
  document.getElementById("btnVerify").addEventListener("click", runVerifyQueue);
  document.getElementById("btnReverifyApproved").addEventListener("click", runReverifyApproved);
  document.getElementById("btnTriageApi").addEventListener("click", runTriageApi);
  document.getElementById("btnTriageExport").addEventListener("click", runTriageExportPrompts);
  document.getElementById("btnTriageImport").addEventListener("click", runTriageImport);
  function setFilterMode(mode) {
    state.filterMode = mode === "illegal" ? "illegal" : "all";
    localStorage.setItem("gallery_filter", state.filterMode);
    const list = visibleItems();
    selectIndex(list.length ? 0 : -1, false);
  }
  if (els.btnFilterAll) els.btnFilterAll.addEventListener("click", () => setFilterMode("all"));
  if (els.btnFilterIllegal) els.btnFilterIllegal.addEventListener("click", () => setFilterMode("illegal"));

  document.getElementById("btnRefresh").addEventListener("click", () => Promise.all([loadQueue(), loadBatches()]));
  document.getElementById("btnRefreshBatches").addEventListener("click", loadBatches);
  document.getElementById("btnExport").addEventListener("click", exportNext20);
  document.getElementById("btnApprove").addEventListener("click", () => submitDecision("approve"));
  document.getElementById("btnApproveNote").addEventListener("click", () => submitDecision("approve_note"));
  document.getElementById("btnSkip").addEventListener("click", () => submitDecision("skip"));
  document.getElementById("btnCloseExport").addEventListener("click", () => els.exportModal.classList.remove("open"));
  document.getElementById("btnCopyExport").addEventListener("click", async () => {
    await copyText(els.exportTextarea.value);
    showToast("Link batch disalin ke clipboard.");
  });
  document.getElementById("btnModalSubmitted").addEventListener("click", async () => {
    if (state.lastExportBatchId) {
      await markBatchStatus(state.lastExportBatchId, "submitted");
      els.exportModal.classList.remove("open");
    }
  });
  document.getElementById("btnModalClaimed").addEventListener("click", async () => {
    if (state.lastExportBatchId) {
      await markBatchStatus(state.lastExportBatchId, "claimed_external");
      els.exportModal.classList.remove("open");
    }
  });

  els.inspImg.addEventListener("click", () => {
    if (!els.inspImg.src) return;
    els.zoomImg.src = els.inspImg.src;
    els.zoomModal.classList.add("open");
  });
  els.zoomModal.addEventListener("click", () => els.zoomModal.classList.remove("open"));

  document.addEventListener("keydown", async (ev) => {
    const tag = (ev.target && ev.target.tagName) ? ev.target.tagName.toLowerCase() : "";
    const isTyping = tag === "input" || tag === "textarea" || tag === "select";

    if (ev.key === "Escape") {
      els.exportModal.classList.remove("open");
      els.zoomModal.classList.remove("open");
      if (isTyping) ev.target.blur();
      return;
    }

    if (ev.target === els.noteInput && ev.key === "Enter" && !ev.shiftKey) {
      ev.preventDefault();
      await submitDecision("approve_note");
      return;
    }

    if (isTyping || ev.ctrlKey || ev.metaKey || ev.altKey) return;

    const key = ev.key.toLowerCase();
    if (key === "a") {
      ev.preventDefault();
      await submitDecision("approve");
    } else if (key === "n") {
      ev.preventDefault();
      if (currentItem()) {
        els.noteInput.focus();
        els.noteInput.select();
        showToast("Edit catatan (maks 140 char), lalu Enter untuk Approve.");
      }
    } else if (key === "x") {
      ev.preventDefault();
      await submitDecision("skip");
    } else if (key === "arrowright" || key === "j") {
      ev.preventDefault();
      await selectIndex(state.selectedIndex + 1, true);
    } else if (key === "arrowleft" || key === "k") {
      ev.preventDefault();
      await selectIndex(state.selectedIndex - 1, true);
    }
  });

  loadQueue();
  loadBatches();
})();
