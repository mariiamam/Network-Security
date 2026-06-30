const form = document.querySelector("#emailForm");
const senderInput = document.querySelector("#sender");
const replyToInput = document.querySelector("#replyTo");
const claimedBrandInput = document.querySelector("#claimedBrand");
const subjectInput = document.querySelector("#subject");
const modeInput = document.querySelector("#mode");
const receivedHopsInput = document.querySelector("#receivedHops");
const bodyInput = document.querySelector("#emailBody");
const sampleSelect = document.querySelector("#sampleSelect");
const clearBtn = document.querySelector("#clearBtn");
const runEvaluation = document.querySelector("#runEvaluation");
const analyzeBtn = document.querySelector("#analyzeBtn");
const validationMessage = document.querySelector("#validationMessage");
const resultPanel = document.querySelector(".result-panel");
const analysisStatus = document.querySelector("#analysisStatus");
const analysisMessage = document.querySelector("#analysisMessage");
const analysisElapsed = document.querySelector("#analysisElapsed");
const analysisSteps = document.querySelector("#analysisSteps");

const riskPill = document.querySelector("#riskPill");
const scoreRing = document.querySelector("#scoreRing");
const scoreValue = document.querySelector("#scoreValue");
const verdict = document.querySelector("#verdict");
const summary = document.querySelector("#summary");
const findingsList = document.querySelector("#findingsList");
const passedList = document.querySelector("#passedList");
const explanation = document.querySelector("#explanation");
const reportText = document.querySelector("#reportText");
const riskMarker = document.querySelector(".risk-bar span");
const metrics = document.querySelector("#metrics");

const ruleVerdict = document.querySelector("#ruleVerdict");
const ruleScore = document.querySelector("#ruleScore");
const assistantVerdict = document.querySelector("#assistantVerdict");
const assistantMeta = document.querySelector("#assistantMeta");
const finalVerdict = document.querySelector("#finalVerdict");
const finalScore = document.querySelector("#finalScore");
const assistantSummary = document.querySelector("#assistantSummary");
const assistantReasons = document.querySelector("#assistantReasons");
const assistantActions = document.querySelector("#assistantActions");
const assistantJson = document.querySelector("#assistantJson");

const riskColors = {
  Low: "#197a4d",
  Medium: "#b56a00",
  High: "#c93535"
};

sampleEmails.forEach((sample, index) => {
  const option = document.createElement("option");
  option.value = String(index);
  option.textContent = sample.name;
  sampleSelect.appendChild(option);
});

let isAnalyzing = false;
let analysisStepTimer = null;
let analysisElapsedTimer = null;
let analysisStartMs = 0;
let analysisUxToken = 0;
let analysisHideTimeout = null;
let analysisEnableTimeout = null;
let analysisRunToken = 0;

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (isAnalyzing) return;

  const formData = readForm();
  clearValidation();
  if (!hasEmailInput(formData)) {
    showValidation("Please enter email details or load a sample before analyzing.");
    return;
  }

  const runToken = (analysisRunToken += 1);
  isAnalyzing = true;
  resultPanel.classList.remove("has-error");
  startAnalysisUx();

  try {
    const result = await analyzeEmailAssisted(formData);
    if (runToken !== analysisRunToken) return;
    renderResult(result);
    stopAnalysisUx({ ok: true, usedAssistant: Boolean(result?.llmUsed) });
  } catch (error) {
    if (runToken !== analysisRunToken) return;
    stopAnalysisUx({ ok: false });
    resultPanel.classList.add("has-error");
    console.error("Analysis failed:", error);
  } finally {
    if (runToken === analysisRunToken) isAnalyzing = false;
  }
});

sampleSelect.addEventListener("change", () => {
  if (sampleSelect.value === "") return;
  if (isAnalyzing) return;
  const sample = sampleEmails[Number(sampleSelect.value)];
  senderInput.value = sample.sender;
  replyToInput.value = sample.replyTo;
  claimedBrandInput.value = sample.claimedBrand;
  subjectInput.value = sample.subject;
  modeInput.value = "balanced";
  receivedHopsInput.value = sample.receivedHops ?? "";
  bodyInput.value = sample.body;
  clearValidation();
});

clearBtn.addEventListener("click", () => {
  analysisRunToken += 1;
  isAnalyzing = false;
  resetAnalysisUx();
  form.reset();
  sampleSelect.value = "";
  clearValidation();
  renderEmpty();
});

runEvaluation.addEventListener("click", () => {
  const result = evaluateSamples(sampleEmails, modeInput.value);
  metrics.innerHTML = `
    <div><strong>${toPercent(result.accuracy)}</strong><span>Accuracy</span></div>
    <div><strong>${toPercent(result.precision)}</strong><span>Precision</span></div>
    <div><strong>${toPercent(result.recall)}</strong><span>Recall</span></div>
    <div><strong>${result.falsePositives}</strong><span>False Positives</span></div>
    <div><strong>${result.truePositives}</strong><span>True Positives</span></div>
    <div><strong>${result.trueNegatives}</strong><span>True Negatives</span></div>
    <div><strong>${result.falseNegatives}</strong><span>False Negatives</span></div>
    <div><strong>${result.total}</strong><span>Samples</span></div>
  `;
});

function readForm() {
  return {
    sender: senderInput.value,
    replyTo: replyToInput.value,
    claimedBrand: claimedBrandInput.value,
    mode: modeInput.value,
    receivedHops: receivedHopsInput.value,
    subject: subjectInput.value,
    body: bodyInput.value
  };
}

function renderResult(result) {
  const color = riskColors[result.risk];
  const rule = result.rule || result;
  const llm = result.llmSummary;
  scoreValue.textContent = result.score;
  scoreRing.style.background = `conic-gradient(${color} ${result.score * 3.6}deg, #d9e0e7 0deg)`;
  riskMarker.style.left = `calc(${result.score}% - 3px)`;
  verdict.textContent = `${result.risk} risk`;
  summary.textContent = result.risk === "High"
    ? "The email is likely phishing and should not be trusted without verification."
    : result.risk === "Medium"
      ? "The email shows suspicious signals and should be verified carefully before trusting."
      : "The email is not strongly suspicious based on the available signals.";
  riskPill.textContent = `${result.risk} risk - ${result.score}/100`;
  riskPill.style.background = color;
  riskPill.style.borderColor = color;
  explanation.textContent = result.explanation;
  reportText.value = result.report;

  ruleVerdict.textContent = `${rule.risk} risk`;
  ruleScore.textContent = `${rule.score}/100`;
  ruleVerdict.style.color = riskColors[rule.risk] || "#18212b";

  if (result.llmUsed && llm) {
    assistantVerdict.textContent = `${llm.verdict.toUpperCase()} risk`;
    assistantMeta.textContent = `${Math.round(llm.confidence * 100)}% confidence · goal: ${String(llm.likely_goal || "unknown").replace("_", " ")}`;
    assistantSummary.textContent = llm.summary || "Assistant summary unavailable.";
    assistantReasons.innerHTML = "";
    (llm.reasons || []).slice(0, 6).forEach((reason) => {
      const item = document.createElement("li");
      item.textContent = reason;
      assistantReasons.appendChild(item);
    });
    if (!assistantReasons.children.length) {
      const item = document.createElement("li");
      item.textContent = "No notable assistant signals were provided.";
      assistantReasons.appendChild(item);
    }

    assistantActions.innerHTML = "";
    (llm.recommended_actions || []).slice(0, 5).forEach((action) => {
      const item = document.createElement("li");
      item.textContent = action;
      assistantActions.appendChild(item);
    });
    if (!assistantActions.children.length) {
      const item = document.createElement("li");
      item.textContent = "No recommended actions were provided.";
      assistantActions.appendChild(item);
    }

    assistantJson.textContent = JSON.stringify(llm, null, 2);
    const assistantKey = `${String(llm.verdict || "").slice(0, 1).toUpperCase()}${String(llm.verdict || "").slice(1)}`;
    assistantVerdict.style.color = riskColors[assistantKey] || "#18212b";
  } else {
    assistantVerdict.textContent = "Unavailable";
    assistantMeta.textContent = "Using rule-based fallback.";
    assistantSummary.textContent = "Assistant is unavailable. Showing rule-based verdict and indicators.";
    assistantReasons.innerHTML = "<li>No assistant summary available.</li>";
    assistantActions.innerHTML = "<li>No recommended actions available.</li>";
    assistantJson.textContent = "";
    assistantVerdict.style.color = "#657385";
  }

  finalVerdict.textContent = `${result.risk} risk`;
  finalScore.textContent = `${result.score}/100`;
  finalVerdict.style.color = riskColors[result.risk] || "#18212b";

  findingsList.innerHTML = "";
  if (!result.findings.length) {
    const item = document.createElement("li");
    item.className = "low";
    item.textContent = "No strong indicators detected.";
    findingsList.appendChild(item);
  } else {
    result.findings.forEach((finding) => {
      const item = document.createElement("li");
      item.className = finding.severity;
      item.innerHTML = `<strong>${escapeHtml(finding.label)}</strong><br>${escapeHtml(finding.detail)}`;
      findingsList.appendChild(item);
    });
  }

  passedList.innerHTML = "";
  if (!result.passedChecks.length) {
    const item = document.createElement("li");
    item.textContent = "No positive checks available.";
    passedList.appendChild(item);
    return;
  }

  result.passedChecks.forEach((check) => {
    const item = document.createElement("li");
    item.textContent = check;
    passedList.appendChild(item);
  });
}

function renderEmpty() {
  riskPill.textContent = "Waiting for email";
  riskPill.style.background = "rgba(255, 255, 255, 0.1)";
  riskPill.style.borderColor = "rgba(255, 255, 255, 0.3)";
  scoreValue.textContent = "--";
  scoreRing.style.background = "conic-gradient(#d9e0e7 0deg, #d9e0e7 360deg)";
  riskMarker.style.left = "0%";
  verdict.textContent = "No analysis yet";
  summary.textContent = "Enter an email and analyze it with rules + assistant.";
  findingsList.innerHTML = "<li>No indicators yet.</li>";
  passedList.innerHTML = "<li>No checks have passed yet.</li>";
  explanation.textContent = "The tool combines content, sender, URL, and impersonation checks.";
  reportText.value = "";

  ruleVerdict.textContent = "--";
  ruleScore.textContent = "--";
  assistantVerdict.textContent = "--";
  assistantMeta.textContent = "--";
  finalVerdict.textContent = "--";
  finalScore.textContent = "--";
  ruleVerdict.style.color = "#18212b";
  assistantVerdict.style.color = "#18212b";
  finalVerdict.style.color = "#18212b";
  assistantSummary.textContent = "Assistant summary will appear after analysis.";
  assistantReasons.innerHTML = "<li>No assistant summary yet.</li>";
  assistantActions.innerHTML = "<li>Run an analysis to see suggested next steps.</li>";
  assistantJson.textContent = "";
}

function hasEmailInput(formData) {
  const hasText = (value) => String(value || "").trim().length > 0;

  return [
    formData?.sender,
    formData?.replyTo,
    formData?.claimedBrand,
    formData?.subject,
    formData?.body,
    formData?.receivedHops
  ].some(hasText);
}

function showValidation(message, { kind = "warning" } = {}) {
  if (!validationMessage) return;
  validationMessage.textContent = message;
  validationMessage.classList.add("is-visible");
  validationMessage.classList.toggle("is-error", kind === "error");
}

function clearValidation() {
  if (!validationMessage) return;
  validationMessage.textContent = "";
  validationMessage.classList.remove("is-visible");
  validationMessage.classList.remove("is-error");
}

function startAnalysisUx() {
  analysisUxToken += 1;
  clearTimeout(analysisHideTimeout);
  clearTimeout(analysisEnableTimeout);
  analysisHideTimeout = null;
  analysisEnableTimeout = null;

  if (analysisStatus) {
    analysisStatus.dataset.outcome = "";
  }

  if (analyzeBtn) {
    analyzeBtn.disabled = true;
    analyzeBtn.dataset.loading = "true";
    const label = analyzeBtn.querySelector(".btn-label");
    if (label) label.textContent = "Analyzing";
  }

  if (sampleSelect) sampleSelect.disabled = true;

  if (analysisStatus) {
    analysisStatus.classList.add("is-active");
  }

  if (resultPanel) {
    resultPanel.classList.add("is-loading");
    resultPanel.setAttribute("aria-busy", "true");
  }

  analysisStartMs = performance.now();
  setAnalysisMessage("Analyzing suspicious indicators...");
  setActiveStep(0);

  clearInterval(analysisElapsedTimer);
  analysisElapsedTimer = setInterval(() => {
    const elapsed = (performance.now() - analysisStartMs) / 1000;
    if (analysisElapsed) analysisElapsed.textContent = `${elapsed.toFixed(1)}s`;
  }, 100);

  clearInterval(analysisStepTimer);
  const stepMessages = [
    "Analyzing suspicious indicators...",
    "Inspecting sender reputation...",
    "Evaluating phishing patterns...",
    "Running AI-assisted analysis...",
    "Finalizing verdict..."
  ];

  let activeIndex = 0;
  analysisStepTimer = setInterval(() => {
    const elapsed = (performance.now() - analysisStartMs) / 1000;
    const nextIndex = elapsed < 0.7
      ? 0
      : elapsed < 1.4
        ? 1
        : elapsed < 2.1
          ? 2
          : elapsed < 3.0
            ? 3
            : 4;

    if (nextIndex !== activeIndex) {
      activeIndex = nextIndex;
      setActiveStep(activeIndex);
      setAnalysisMessage(stepMessages[activeIndex]);
    }
  }, 160);
}

function stopAnalysisUx({ ok, usedAssistant } = {}) {
  const token = analysisUxToken;
  clearInterval(analysisStepTimer);
  clearInterval(analysisElapsedTimer);
  analysisStepTimer = null;
  analysisElapsedTimer = null;

  if (ok) {
    if (usedAssistant) {
      setAnalysisMessage("Assistant analysis complete. Finalizing report...");
      if (analysisStatus) analysisStatus.dataset.outcome = "ok";
    } else {
      setAnalysisMessage("Assistant unavailable. Using safe fallback...");
      if (analysisStatus) analysisStatus.dataset.outcome = "fallback";
    }
    setActiveStep(4);
  } else {
    setAnalysisMessage("Analysis failed. Please try again.");
    if (analysisStatus) analysisStatus.dataset.outcome = "error";
    if (resultPanel) resultPanel.classList.add("has-error");
  }

  const elapsed = (performance.now() - analysisStartMs) / 1000;
  if (analysisElapsed) analysisElapsed.textContent = `${Math.max(0, elapsed).toFixed(1)}s`;

  analysisHideTimeout = window.setTimeout(() => {
    if (token !== analysisUxToken) return;
    if (analysisStatus) analysisStatus.classList.remove("is-active");
    if (resultPanel) {
      resultPanel.classList.remove("is-loading");
      resultPanel.removeAttribute("aria-busy");
    }
  }, ok ? 420 : 900);

  analysisEnableTimeout = window.setTimeout(() => {
    if (token !== analysisUxToken) return;
    if (analyzeBtn) {
      analyzeBtn.disabled = false;
      analyzeBtn.dataset.loading = "false";
      const label = analyzeBtn.querySelector(".btn-label");
      if (label) label.textContent = "Analyze";
    }

    if (sampleSelect) sampleSelect.disabled = false;
  }, ok ? 260 : 650);
}

function resetAnalysisUx() {
  analysisUxToken += 1;
  clearInterval(analysisStepTimer);
  clearInterval(analysisElapsedTimer);
  clearTimeout(analysisHideTimeout);
  clearTimeout(analysisEnableTimeout);
  analysisStepTimer = null;
  analysisElapsedTimer = null;
  analysisHideTimeout = null;
  analysisEnableTimeout = null;

  if (analysisStatus) {
    analysisStatus.dataset.outcome = "";
    analysisStatus.classList.remove("is-active");
  }

  if (resultPanel) {
    resultPanel.classList.remove("is-loading");
    resultPanel.classList.remove("has-error");
    resultPanel.removeAttribute("aria-busy");
  }

  if (analyzeBtn) {
    analyzeBtn.disabled = false;
    analyzeBtn.dataset.loading = "false";
    const label = analyzeBtn.querySelector(".btn-label");
    if (label) label.textContent = "Analyze";
  }

  if (clearBtn) clearBtn.disabled = false;
  if (sampleSelect) sampleSelect.disabled = false;
}

function setAnalysisMessage(text) {
  if (!analysisMessage) return;
  analysisMessage.textContent = text;
}

function setActiveStep(activeIndex) {
  if (!analysisSteps) return;
  const items = Array.from(analysisSteps.querySelectorAll("li"));
  items.forEach((item, index) => {
    item.classList.toggle("is-active", index === activeIndex);
    item.classList.toggle("is-done", index < activeIndex);
  });
}

function toPercent(value) {
  return `${Math.round(value * 100)}%`;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

[senderInput, replyToInput, claimedBrandInput, subjectInput, bodyInput, receivedHopsInput].forEach((input) => {
  if (!input) return;
  input.addEventListener("input", () => clearValidation());
});
