import {
  TEMPLATES,
  analyzePolicy,
  buildLiveVerificationPlan,
  buildRialoPayload,
  createReceipt,
  hardenPolicy,
  normalizePolicy,
} from "./engine.js";

const editor = document.querySelector("#policyEditor");
const lineNumbers = document.querySelector("#lineNumbers");
const editorState = document.querySelector("#editorState");
const editorStateText = document.querySelector("#editorStateText");
const templateSelect = document.querySelector("#templateSelect");
const findingsList = document.querySelector("#findingsList");
const testList = document.querySelector("#testList");
const toast = document.querySelector("#toast");
const guideModal = document.querySelector("#guideModal");
const guideOpen = document.querySelector("#guideOpen");
const guideClose = document.querySelector("#guideClose");
const liveVerifyModal = document.querySelector("#liveVerifyModal");
const liveVerifyButton = document.querySelector("#liveVerifyButton");
const liveVerifyClose = document.querySelector("#liveVerifyClose");
const liveVerifyForm = document.querySelector("#liveVerifyForm");
const liveVerifyRun = document.querySelector("#liveVerifyRun");
const liveVerifyResults = document.querySelector("#liveVerifyResults");
const latchTokenInput = document.querySelector("#latchToken");

let analysis = null;
let receipt = null;
let rialoPayload = null;
let liveVerification = null;
let activeSeverity = "all";
let toastTimer = null;
let guideReturnFocus = null;
let liveReturnFocus = null;
let liveRunController = null;

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function pretty(value) {
  return JSON.stringify(value, null, 2);
}

function setEditor(value) {
  editor.value = pretty(value);
  updateLineNumbers();
  setEditorState("ready");
}

function setEditorState(state, text) {
  editorState.classList.toggle("error", state === "error");
  editorStateText.textContent = text || state;
}

function updateLineNumbers() {
  const count = Math.max(1, editor.value.split("\n").length);
  lineNumbers.innerHTML = Array.from(
    { length: count },
    (_, index) => index + 1,
  ).join("<br>");
  lineNumbers.scrollTop = editor.scrollTop;
}

function showToast(message, kind) {
  window.clearTimeout(toastTimer);
  toast.textContent = message;
  toast.classList.toggle("error", kind === "error");
  toast.classList.add("visible");
  toastTimer = window.setTimeout(
    () => toast.classList.remove("visible"),
    2600,
  );
}

function headlineFor(result) {
  if (result.score >= 90) return "Strong boundary, verify live";
  if (result.score >= 75) return "Close, but review the edges";
  if (result.score >= 50) return "Material gaps remain";
  return "Policy needs containment";
}

function descriptionFor(result) {
  if (result.score >= 90) {
    return "The local attack deck found a narrow blast radius. Confirm stateful filters with Latch Simulate.";
  }
  if (result.score >= 75) {
    return "Most attack paths are contained, but one weak boundary can still dominate the risk.";
  }
  if (result.score >= 50) {
    return "Several useful controls exist, yet adversarial requests can still escape the intended scope.";
  }
  return "High-impact requests can reach authority that the agent should not possess.";
}

function scoreColor(score) {
  if (score >= 90) return "#2f9b6e";
  if (score >= 75) return "#4d88bd";
  if (score >= 50) return "#d39337";
  return "#df6259";
}

function renderSummary(result) {
  const ring = document.querySelector("#scoreRing");
  ring.style.setProperty("--score", result.score);
  ring.style.setProperty("--ring-color", scoreColor(result.score));
  document.querySelector("#scoreValue").textContent = result.score;
  document.querySelector("#policyName").textContent =
    result.policy.name || "Imported policy";
  document.querySelector("#scoreHeadline").textContent = headlineFor(result);
  document.querySelector("#scoreDescription").textContent =
    descriptionFor(result);
  document.querySelector("#passedCount").textContent = result.passed;
  document.querySelector("#failedCount").textContent = result.failed;
  document.querySelector("#criticalCount").textContent =
    result.counts.critical;
  document.querySelector("#findingTotal").textContent =
    result.findings.length;

  const badge = document.querySelector("#gradeBadge");
  badge.textContent = result.grade;
  badge.className = "grade-badge grade-" + result.grade.toLowerCase();
}

function renderFindings(result) {
  const visible = result.findings.filter(
    (item) => activeSeverity === "all" || item.severity === activeSeverity,
  );
  if (!visible.length) {
    findingsList.innerHTML =
      '<div class="empty-state">No findings in this severity. Keep the proof, then verify the live pipeline.</div>';
    return;
  }

  findingsList.innerHTML = visible
    .map(
      (item, index) =>
        '<article class="finding-item">' +
        '<button class="finding-trigger" type="button" aria-expanded="false">' +
        '<span class="severity-mark ' +
        escapeHtml(item.severity) +
        '"></span>' +
        '<span class="finding-title"><strong>' +
        escapeHtml(item.title) +
        "</strong><span>" +
        escapeHtml(item.severity) +
        " · " +
        escapeHtml(item.code) +
        "</span></span>" +
        '<span class="finding-chevron" aria-hidden="true">+</span>' +
        "</button>" +
        '<div class="finding-detail" id="finding-detail-' +
        index +
        '">' +
        "<p>" +
        escapeHtml(item.detail) +
        "</p>" +
        '<div class="fix-line"><strong>Fix:</strong> ' +
        escapeHtml(item.fix) +
        "</div>" +
        "</div>" +
        "</article>",
    )
    .join("");

  findingsList.querySelectorAll(".finding-trigger").forEach((button) => {
    button.addEventListener("click", () => {
      const item = button.closest(".finding-item");
      const open = item.classList.toggle("open");
      button.setAttribute("aria-expanded", String(open));
    });
  });
}

function traceMarkup(test) {
  if (!test.trace?.length) {
    return '<div class="fix-line">This is a structural test; no request trace was needed.</div>';
  }
  return (
    '<div class="trace-list">' +
    test.trace
      .map(
        (step) =>
          '<div class="trace-row ' +
          escapeHtml(step.outcome) +
          '"><b>' +
          escapeHtml(step.outcome) +
          "</b><span>" +
          escapeHtml(step.filter) +
          " — " +
          escapeHtml(step.detail) +
          "</span></div>",
      )
      .join("") +
    "</div>"
  );
}

function renderTests(result) {
  testList.innerHTML = result.tests
    .map(
      (test) =>
        '<article class="test-item">' +
        '<button class="test-trigger" type="button" aria-expanded="false">' +
        '<span class="test-status ' +
        escapeHtml(test.status) +
        '"></span>' +
        '<span class="test-title"><strong>' +
        escapeHtml(test.title) +
        "</strong><span>" +
        escapeHtml(test.category) +
        " · expected " +
        escapeHtml(test.expected) +
        "</span></span>" +
        '<span class="finding-chevron" aria-hidden="true">+</span>' +
        "</button>" +
        '<div class="test-detail"><p><strong>' +
        (test.status === "pass" ? "Protected." : "Exposed.") +
        "</strong> " +
        escapeHtml(test.reason || test.remediation) +
        "</p>" +
        traceMarkup(test) +
        '<div class="fix-line"><strong>Recommendation:</strong> ' +
        escapeHtml(test.remediation) +
        "</div></div>" +
        "</article>",
    )
    .join("");

  testList.querySelectorAll(".test-trigger").forEach((button) => {
    button.addEventListener("click", () => {
      const item = button.closest(".test-item");
      const open = item.classList.toggle("open");
      button.setAttribute("aria-expanded", String(open));
    });
  });
}

function shortHash(value) {
  if (!value) return "—";
  return value.slice(0, 12) + "…" + value.slice(-12);
}

function renderProof(nextReceipt, payload) {
  const comparedLive = nextReceipt.mode === "latch-authorize-compared";
  document.querySelector("#receiptStatus").textContent = comparedLive
    ? "Receipt binds the live comparison"
    : "Deterministic local receipt generated";
  document.querySelector("#reportMode").textContent = comparedLive
    ? "live compared"
    : "draft proof";
  document.querySelector("#policyHash").textContent = shortHash(
    nextReceipt.policyHash,
  );
  document.querySelector("#policyHash").title = nextReceipt.policyHash;
  document.querySelector("#reportHash").textContent = shortHash(
    nextReceipt.reportHash,
  );
  document.querySelector("#reportHash").title = nextReceipt.reportHash;
  document.querySelector("#generatedAt").textContent = new Date(
    nextReceipt.generatedAt,
  ).toLocaleString();
  document.querySelector("#payloadPreview").textContent = pretty(payload);
}

function resetLiveVerification() {
  liveVerification = null;
  document.querySelector("#reportMode").textContent = "draft proof";
  if (liveVerifyResults) {
    liveVerifyResults.hidden = true;
    liveVerifyResults.innerHTML = "";
  }
}

async function runAnalysis(options) {
  const quiet = options?.quiet;
  resetLiveVerification();
  try {
    setEditorState("running");
    const policy = normalizePolicy(editor.value);
    analysis = analyzePolicy(policy);
    receipt = await createReceipt(analysis);
    rialoPayload = buildRialoPayload(receipt);
    renderSummary(analysis);
    renderFindings(analysis);
    renderTests(analysis);
    renderProof(receipt, rialoPayload);
    localStorage.setItem("latchlens.policy", pretty(policy));
    setEditorState("valid");
    if (!quiet) {
      showToast(
        "Suite complete: " +
          analysis.passed +
          " protected, " +
          analysis.failed +
          " exposed.",
      );
    }
    return analysis;
  } catch (error) {
    setEditorState("error", "invalid JSON");
    showToast(error.message || "Policy could not be parsed.", "error");
    return null;
  }
}

function selectTab(name) {
  document.querySelectorAll(".tab-button").forEach((button) => {
    const active = button.dataset.tab === name;
    button.classList.toggle("active", active);
    button.setAttribute("aria-selected", String(active));
  });
  document.querySelectorAll(".tab-panel").forEach((panel) => {
    const active = panel.id === name + "Panel";
    panel.classList.toggle("active", active);
    panel.hidden = !active;
  });
}

function loadTemplate(key, announce) {
  const template = TEMPLATES[key] || TEMPLATES.unsafe;
  setEditor(template.policy);
  runAnalysis({ quiet: true });
  if (announce) showToast(template.label + " loaded.");
}

function applyHardening() {
  try {
    const before = analyzePolicy(editor.value);
    const hardened = hardenPolicy(editor.value);
    setEditor(hardened);
    runAnalysis({ quiet: true }).then((after) => {
      if (after) {
        showToast(
          "Safe defaults applied: score " +
            before.score +
            " → " +
            after.score +
            ". Review placeholders.",
        );
      }
    });
  } catch (error) {
    showToast(error.message || "Hardening patch failed.", "error");
  }
}

function downloadJson(filename, value) {
  const blob = new Blob([pretty(value)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

async function copyText(value, message) {
  try {
    await navigator.clipboard.writeText(value);
    showToast(message);
  } catch {
    showToast("Clipboard access was unavailable.", "error");
  }
}

function jumpToLab() {
  document.querySelector("#lab").scrollIntoView({ behavior: "smooth" });
  window.setTimeout(() => runAnalysis(), 420);
}

function openGuide() {
  guideReturnFocus = document.activeElement;
  guideModal.hidden = false;
  document.body.classList.add("guide-open");
  guideOpen.setAttribute("aria-expanded", "true");
  guideClose.focus();
}

function closeGuide(options) {
  const restoreFocus = options?.restoreFocus !== false;
  guideModal.hidden = true;
  document.body.classList.remove("guide-open");
  guideOpen.setAttribute("aria-expanded", "false");
  if (restoreFocus && guideReturnFocus instanceof HTMLElement) {
    guideReturnFocus.focus();
  }
}

function keepGuideFocus(event) {
  if (event.key === "Escape") {
    closeGuide();
    return;
  }
  if (event.key !== "Tab") return;

  const focusable = Array.from(
    guideModal.querySelectorAll("button, [href], input, select, textarea, [tabindex]:not([tabindex='-1'])"),
  ).filter((item) => !item.disabled && !item.hidden);
  if (!focusable.length) return;

  const first = focusable[0];
  const last = focusable.at(-1);
  if (event.shiftKey && document.activeElement === first) {
    event.preventDefault();
    last.focus();
  } else if (!event.shiftKey && document.activeElement === last) {
    event.preventDefault();
    first.focus();
  }
}

function openLiveVerify() {
  liveReturnFocus = document.activeElement;
  liveVerifyModal.hidden = false;
  document.body.classList.add("guide-open");
  liveVerifyButton.setAttribute("aria-expanded", "true");
  latchTokenInput.focus();
}

function closeLiveVerify(options) {
  const restoreFocus = options?.restoreFocus !== false;
  if (liveRunController) liveRunController.abort();
  latchTokenInput.value = "";
  liveVerifyModal.hidden = true;
  document.body.classList.remove("guide-open");
  liveVerifyButton.setAttribute("aria-expanded", "false");
  if (restoreFocus && liveReturnFocus instanceof HTMLElement) {
    liveReturnFocus.focus();
  }
}

function keepLiveFocus(event) {
  if (event.key === "Escape") {
    closeLiveVerify();
    return;
  }
  if (event.key !== "Tab") return;

  const focusable = Array.from(
    liveVerifyModal.querySelectorAll(
      "button, [href], input, select, textarea, [tabindex]:not([tabindex='-1'])",
    ),
  ).filter((item) => !item.disabled && !item.hidden);
  if (!focusable.length) return;

  const first = focusable[0];
  const last = focusable.at(-1);
  if (event.shiftKey && document.activeElement === first) {
    event.preventDefault();
    last.focus();
  } else if (!event.shiftKey && document.activeElement === last) {
    event.preventDefault();
    first.focus();
  }
}

function renderLiveProgress(completed, total, title) {
  liveVerifyResults.hidden = false;
  liveVerifyResults.innerHTML =
    '<div class="live-progress" role="status"><strong>Checking ' +
    escapeHtml(String(completed + 1)) +
    " of " +
    escapeHtml(String(total)) +
    "</strong><p>" +
    escapeHtml(title) +
    "</p></div>";
}

function renderLiveError(message) {
  liveVerifyResults.hidden = false;
  liveVerifyResults.innerHTML =
    '<div class="live-summary has-mismatch" role="alert"><strong>Live verification stopped</strong><p>' +
    escapeHtml(message) +
    " No token was saved.</p></div>";
}

function renderLiveResults(verification) {
  const allMatched = verification.mismatched === 0;
  const summary = allMatched
    ? verification.matched +
      "/" +
      verification.checked +
      " canonical decisions matched the local mirror."
    : verification.mismatched +
      " decision(s) differed. Confirm that the token belongs to this policy and inspect the first-deny trace.";
  const items = verification.results
    .map((result) => {
      const trace = result.filterResults?.length
        ? '<pre aria-label="Latch filter trace">' +
          escapeHtml(pretty(result.filterResults)) +
          "</pre>"
        : "<p>Latch returned no per-filter trace for this decision.</p>";
      return (
        '<details class="live-result ' +
        (result.matched ? "match" : "mismatch") +
        '"><summary><span class="live-result-dot" aria-hidden="true"></span>' +
        '<span class="live-result-title"><strong>' +
        escapeHtml(result.title) +
        "</strong><span>expected " +
        escapeHtml(result.expected) +
        " · Latch " +
        escapeHtml(result.decision) +
        "</span></span><b>" +
        (result.matched ? "match" : "review") +
        '</b></summary><div class="live-result-detail"><p><strong>Request:</strong> ' +
        escapeHtml(result.method + " " + result.path) +
        "</p>" +
        (result.deniedBy
          ? "<p><strong>First deny:</strong> " +
            escapeHtml(result.deniedBy) +
            (result.deniedReason
              ? " — " + escapeHtml(result.deniedReason)
              : "") +
            "</p>"
          : "") +
        (result.requestId
          ? "<p><strong>Request ID:</strong> " +
            escapeHtml(result.requestId) +
            "</p>"
          : "") +
        trace +
        "</div></details>"
      );
    })
    .join("");

  liveVerifyResults.hidden = false;
  liveVerifyResults.innerHTML =
    '<div class="live-summary ' +
    (allMatched ? "" : "has-mismatch") +
    '"><strong>Live comparison complete</strong><p>' +
    escapeHtml(summary) +
    " " +
    escapeHtml(String(verification.skipped)) +
    " context or structural cases stayed local.</p></div>" +
    '<div class="live-result-list">' +
    items +
    "</div>";
}

async function requestLatchDecision(token, test, signal) {
  const response = await fetch("/api/latch-authorize", {
    method: "POST",
    headers: {
      authorization: "Bearer " + token,
      "content-type": "application/json",
    },
    body: JSON.stringify(test.request),
    cache: "no-store",
    signal,
  });

  let data = {};
  try {
    data = await response.json();
  } catch {
    throw new Error("The verification adapter returned an invalid response.");
  }
  if (!response.ok) {
    throw new Error(data.error || "Latch rejected the verification request.");
  }
  return data;
}

async function runLiveVerification(event) {
  event.preventDefault();
  let token = latchTokenInput.value.trim();
  latchTokenInput.value = "";

  if (!/^lat_[^\s]+$/.test(token)) {
    token = "";
    renderLiveError("Enter a valid token beginning with lat_.");
    latchTokenInput.focus();
    return;
  }

  const currentAnalysis = await runAnalysis({ quiet: true });
  if (!currentAnalysis) {
    token = "";
    renderLiveError("Fix the policy JSON before live verification.");
    return;
  }

  const plan = buildLiveVerificationPlan(currentAnalysis.policy);
  const results = [];
  liveRunController = new AbortController();
  liveVerifyRun.disabled = true;
  liveVerifyRun.textContent = "Verifying…";

  try {
    for (let index = 0; index < plan.runnable.length; index += 1) {
      const test = plan.runnable[index];
      renderLiveProgress(index, plan.runnable.length, test.title);
      const decision = await requestLatchDecision(
        token,
        test,
        liveRunController.signal,
      );
      results.push({
        id: test.id,
        title: test.title,
        expected: test.expected,
        decision: decision.decision,
        matched: decision.decision === test.expected,
        method: test.request.method,
        path: test.request.path,
        requestId: decision.requestId,
        deniedBy: decision.deniedBy,
        deniedReason: decision.deniedReason,
        filterResults: decision.filterResults || [],
        receiptIssued: Boolean(decision.receiptIssued),
      });
    }

    liveVerification = {
      schema: "latchlens.live-verification.v1",
      endpoint: "POST /proxy/.well-known/latch-self/authorize",
      verifiedAt: new Date().toISOString(),
      checked: results.length,
      matched: results.filter((result) => result.matched).length,
      mismatched: results.filter((result) => !result.matched).length,
      skipped: plan.skipped.length,
      results,
      skippedCases: plan.skipped,
    };
    receipt = await createReceipt(analysis, liveVerification);
    rialoPayload = buildRialoPayload(receipt);
    renderProof(receipt, rialoPayload);
    renderLiveResults(liveVerification);
    showToast(
      "Live comparison: " +
        liveVerification.matched +
        "/" +
        liveVerification.checked +
        " matched.",
      liveVerification.mismatched ? "error" : undefined,
    );
  } catch (error) {
    if (error?.name !== "AbortError") {
      renderLiveError(error.message || "Live verification failed.");
      showToast(error.message || "Live verification failed.", "error");
    }
  } finally {
    token = "";
    liveRunController = null;
    liveVerifyRun.disabled = false;
    liveVerifyRun.textContent = "Run 6 live checks";
  }
}

editor.addEventListener("input", () => {
  updateLineNumbers();
  setEditorState("edited");
  resetLiveVerification();
});

editor.addEventListener("scroll", () => {
  lineNumbers.scrollTop = editor.scrollTop;
});

editor.addEventListener("keydown", (event) => {
  if (event.key === "Tab") {
    event.preventDefault();
    const start = editor.selectionStart;
    const end = editor.selectionEnd;
    editor.value =
      editor.value.slice(0, start) + "  " + editor.value.slice(end);
    editor.selectionStart = editor.selectionEnd = start + 2;
    updateLineNumbers();
  }
  if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
    event.preventDefault();
    runAnalysis();
  }
});

document
  .querySelector("#runButton")
  .addEventListener("click", () => runAnalysis());
document.querySelector("#formatButton").addEventListener("click", () => {
  try {
    setEditor(normalizePolicy(editor.value));
    showToast("Policy formatted.");
  } catch (error) {
    showToast(error.message, "error");
  }
});
document
  .querySelector("#hardenButton")
  .addEventListener("click", applyHardening);
document.querySelector("#heroRun").addEventListener("click", jumpToLab);
document.querySelector("#closingRun").addEventListener("click", jumpToLab);

guideOpen.addEventListener("click", openGuide);
guideClose.addEventListener("click", () => closeGuide());
document.querySelector("#guideDone").addEventListener("click", () => closeGuide());
guideModal.addEventListener("click", (event) => {
  if (event.target === guideModal) closeGuide();
});
guideModal.addEventListener("keydown", keepGuideFocus);
document.querySelector("#guideTry").addEventListener("click", () => {
  closeGuide({ restoreFocus: false });
  templateSelect.value = "unsafe";
  loadTemplate("unsafe", false);
  selectTab("findings");
  jumpToLab();
});

liveVerifyButton.addEventListener("click", openLiveVerify);
liveVerifyClose.addEventListener("click", () => closeLiveVerify());
document
  .querySelector("#liveVerifyCancel")
  .addEventListener("click", () => closeLiveVerify());
liveVerifyModal.addEventListener("click", (event) => {
  if (event.target === liveVerifyModal) closeLiveVerify();
});
liveVerifyModal.addEventListener("keydown", keepLiveFocus);
liveVerifyForm.addEventListener("submit", runLiveVerification);

templateSelect.addEventListener("change", () =>
  loadTemplate(templateSelect.value, true),
);

document.querySelector("#importButton").addEventListener("click", () => {
  document.querySelector("#fileInput").click();
});

document
  .querySelector("#fileInput")
  .addEventListener("change", async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;
    try {
      const text = await file.text();
      const policy = normalizePolicy(text);
      setEditor(policy);
      await runAnalysis();
      showToast(file.name + " imported.");
    } catch (error) {
      showToast(error.message || "Could not import that file.", "error");
    } finally {
      event.target.value = "";
    }
  });

document.querySelectorAll(".tab-button").forEach((button) => {
  button.addEventListener("click", () => selectTab(button.dataset.tab));
});

document.querySelectorAll(".severity-filter").forEach((button) => {
  button.addEventListener("click", () => {
    activeSeverity = button.dataset.severity;
    document.querySelectorAll(".severity-filter").forEach((item) => {
      item.classList.toggle("active", item === button);
    });
    if (analysis) renderFindings(analysis);
  });
});

document.querySelector("#downloadReport").addEventListener("click", () => {
  if (!analysis || !receipt) {
    showToast("Run the suite before exporting.", "error");
    return;
  }
  downloadJson("latchlens-assurance-report.json", {
    receipt,
    analysis: {
      score: analysis.score,
      grade: analysis.grade,
      counts: analysis.counts,
      findings: analysis.findings,
      tests: analysis.tests.map((test) => ({
        id: test.id,
        title: test.title,
        category: test.category,
        severity: test.severity,
        status: test.status,
        actual: test.actual,
        deniedBy: test.deniedBy,
        reason: test.reason,
        remediation: test.remediation,
        trace: test.trace,
      })),
    },
    ...(liveVerification ? { liveVerification } : {}),
    rialoPayload,
  });
  showToast("Assurance report downloaded.");
});

document.querySelector("#copyReceipt").addEventListener("click", () => {
  if (!receipt) return showToast("Run the suite first.", "error");
  copyText(pretty(receipt), "Receipt copied.");
});

document.querySelector("#copyPayload").addEventListener("click", () => {
  if (!rialoPayload) return showToast("Run the suite first.", "error");
  copyText(pretty(rialoPayload), "Rialo payload copied.");
});

const saved = localStorage.getItem("latchlens.policy");
if (saved) {
  try {
    setEditor(normalizePolicy(saved));
  } catch {
    setEditor(TEMPLATES.unsafe.policy);
  }
} else {
  setEditor(TEMPLATES.unsafe.policy);
}

runAnalysis({ quiet: true });
