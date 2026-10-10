import {
  TEMPLATES,
  analyzePolicy,
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

let analysis = null;
let receipt = null;
let rialoPayload = null;
let activeSeverity = "all";
let toastTimer = null;
let guideReturnFocus = null;

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
  document.querySelector("#receiptStatus").textContent =
    "Deterministic receipt generated";
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

async function runAnalysis(options) {
  const quiet = options?.quiet;
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

editor.addEventListener("input", () => {
  updateLineNumbers();
  setEditorState("edited");
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
