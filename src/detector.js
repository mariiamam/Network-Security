const trustedDomains = {
  paypal: ["paypal.com"],
  microsoft: ["microsoft.com", "office.com", "live.com", "outlook.com"],
  amazon: ["amazon.com"],
  google: ["google.com", "gmail.com"],
  "bank of america": ["bankofamerica.com"],
  university: ["university.edu"],
  "company it": ["company.com"],
  cloudvendor: ["cloudvendor.com"],
  github: ["github.com"],
  "human resources": ["company.com"]
};

const suspiciousTlds = ["ru", "cn", "xyz", "top", "click", "zip", "mov", "tk", "icu", "rest", "support"];
const shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "rebrand.ly", "cutt.ly"];
const freeMailDomains = ["gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "proton.me", "temporarymail.com"];

const modeProfiles = {
  strict: { multiplier: 1.12, phishingThreshold: 45, mediumThreshold: 25 },
  balanced: { multiplier: 1, phishingThreshold: 55, mediumThreshold: 31 },
  relaxed: { multiplier: 0.86, phishingThreshold: 65, mediumThreshold: 40 }
};

const patterns = [
  {
    id: "urgency",
    severity: "medium",
    weight: 16,
    label: "Urgency or pressure language",
    regex: /\b(urgent|immediately|within\s+\d+\s*(minutes|hours)|before midnight|final warning|last chance|today|action required)\b/i
  },
  {
    id: "credentials",
    severity: "high",
    weight: 24,
    label: "Request for credentials or sensitive data",
    regex: /\b(password|username|login|card number|payment details|ssn|social security|verify your account|confirm your password|seed phrase|one-time code|otp)\b/i
  },
  {
    id: "threat",
    severity: "high",
    weight: 20,
    label: "Threat of account suspension or loss",
    regex: /\b(suspended|locked|terminated|unauthorized|suspicious activity|prevent termination|access will be suspended|mailbox will be closed)\b/i
  },
  {
    id: "reward",
    severity: "medium",
    weight: 14,
    label: "Prize, reward, or too-good-to-be-true offer",
    regex: /\b(congratulations|selected|reward|winner|claim your prize|exclusive offer|gift card)\b/i
  },
  {
    id: "paymentPressure",
    severity: "medium",
    weight: 15,
    label: "Payment or invoice pressure",
    regex: /\b(overdue|wire transfer|bank details|invoice attached|past due|remittance|purchase order)\b/i
  },
  {
    id: "genericGreeting",
    severity: "low",
    weight: 8,
    label: "Generic greeting",
    regex: /\b(dear customer|dear user|hello user|valued customer)\b/i
  },
  {
    id: "qrPhishing",
    severity: "medium",
    weight: 13,
    label: "QR-code phishing cue",
    regex: /\b(scan the qr|qr code|use your phone camera)\b/i
  }
];

function analyzeEmail(email) {
  const subject = email.subject || "";
  const body = email.body || "";
  const text = `${subject}\n${body}`;
  const senderDomain = getDomain(email.sender);
  const replyDomain = getDomain(email.replyTo);
  const urls = extractUrls(text);
  const findings = [];
  const passedChecks = [];
  let rawScore = 0;

  patterns.forEach((pattern) => {
    if (pattern.regex.test(text)) {
      rawScore += pattern.weight;
      findings.push({
        severity: pattern.severity,
        label: pattern.label,
        detail: `Matched ${pattern.id.replace(/([A-Z])/g, " $1").toLowerCase()} signal.`
      });
    }
  });

  if (senderDomain && replyDomain && senderDomain !== replyDomain) {
    rawScore += 15;
    findings.push({
      severity: "medium",
      label: "Reply-to domain differs from sender",
      detail: `${email.sender} replies to ${email.replyTo}.`
    });
  } else if (senderDomain && replyDomain) {
    passedChecks.push("Reply-to domain matches the sender domain.");
  }

  rawScore += scoreReceivedHops(email.receivedHops, findings, passedChecks);

  if (senderDomain && isSuspiciousDomain(senderDomain)) {
    rawScore += 12;
    findings.push({
      severity: "medium",
      label: "Suspicious sender domain",
      detail: `Sender uses ${senderDomain}.`
    });
  }

  if (email.claimedBrand && senderDomain && freeMailDomains.includes(senderDomain)) {
    rawScore += 15;
    findings.push({
      severity: "medium",
      label: "Brand mail sent from free-mail domain",
      detail: `${email.claimedBrand} message appears to come from ${senderDomain}.`
    });
  }

  const brandFinding = checkBrandImpersonation(email.claimedBrand, senderDomain, urls);
  if (brandFinding) {
    rawScore += brandFinding.weight;
    findings.push(brandFinding);
  } else if (email.claimedBrand && senderDomain) {
    passedChecks.push("Claimed organization has at least one trusted sender or link domain.");
  }

  urls.forEach((url) => {
    rawScore += scoreUrl(url, findings);
  });

  if (urls.length === 0 && text.trim()) {
    passedChecks.push("No clickable HTTP or HTTPS links were found in the message body.");
  }

  if (!text.trim() && !senderDomain) {
    rawScore = 0;
  }

  const profile = modeProfiles[email.mode] || modeProfiles.balanced;
  const score = Math.max(0, Math.min(100, Math.round(rawScore * profile.multiplier)));
  const risk = classifyRisk(score, profile);
  const dedupedFindings = dedupeFindings(findings);

  return {
    score,
    risk,
    phishing: score >= profile.phishingThreshold,
    findings: dedupedFindings,
    passedChecks: dedupeStrings(passedChecks),
    explanation: buildExplanation(score, risk, dedupedFindings),
    report: buildReport(email, score, risk, dedupedFindings, passedChecks, profile)
  };
}

async function analyzeEmailAssisted(email, options = {}) {
  const ruleResult = analyzeEmail(email);
  const profile = modeProfiles[email?.mode] || modeProfiles.balanced;
  const assistantEnabled = options.assistantEnabled !== false;

  let llmSummary = null;
  let llmUsed = false;
  const preprocessSummary = buildPreprocessSummary(email, ruleResult);

  if (assistantEnabled && isHttpContext() && typeof realLlmSummarizeEmail === "function") {
    try {
      llmSummary = await realLlmSummarizeEmail(preprocessSummary);
      llmUsed = isValidLlmSummary(llmSummary);
    } catch {
      llmSummary = null;
      llmUsed = false;
    }
  }

  if (!llmUsed && assistantEnabled && typeof mockLlmSummarizeEmail === "function") {
    try {
      llmSummary = await mockLlmSummarizeEmail(email);
      llmUsed = isValidLlmSummary(llmSummary);
    } catch {
      llmSummary = null;
      llmUsed = false;
    }
  }

  if (!llmUsed) {
    return {
      ...ruleResult,
      rule: ruleResult,
      llmUsed: false,
      llmSummary: null,
      combined: { score: ruleResult.score, risk: ruleResult.risk, phishing: ruleResult.phishing }
    };
  }

  const llmBand = llmVerdictToScoreBand(llmSummary.verdict);
  const combinedScore = clampScore(Math.round(ruleResult.score * 0.7 + llmBand * 0.3));
  const combinedRisk = classifyRisk(combinedScore, profile);
  const combinedPhishing = combinedScore >= profile.phishingThreshold;
  const combined = { score: combinedScore, risk: combinedRisk, phishing: combinedPhishing };

  const baseExplanation = buildExplanation(combinedScore, combinedRisk, ruleResult.findings);
  const assistedExplanation = [
    baseExplanation,
    `Assistant: rules score ${ruleResult.score}/100 + assistant verdict ${llmSummary.verdict.toUpperCase()} (${Math.round(llmSummary.confidence * 100)}% confidence) → combined ${combinedScore}/100 (${combinedRisk} risk).`
  ].join(" ");

  const baseReport = buildReport(email, combinedScore, combinedRisk, ruleResult.findings, ruleResult.passedChecks, profile);
  const assistedReport = [
    baseReport,
    "",
    "LLM Assist Summary:",
    JSON.stringify(llmSummary, null, 2)
  ].join("\n");

  return {
    ...ruleResult,
    rule: ruleResult,
    score: combinedScore,
    risk: combinedRisk,
    phishing: combinedPhishing,
    explanation: assistedExplanation,
    report: assistedReport,
    llmUsed: true,
    llmSummary,
    combined
  };
}

function buildPreprocessSummary(email, ruleResult) {
  const senderDomain = getDomain(email?.sender);
  const replyToDomain = getDomain(email?.replyTo);
  const receivedHops = normalizeOptionalInt(email?.receivedHops);
  const claimedBrand = String(email?.claimedBrand || "").trim() || null;
  const mode = String(email?.mode || "balanced");
  const urls = extractUrls(`${email?.subject || ""}\n${email?.body || ""}`);

  const urlSummaries = urls
    .slice(0, 12)
    .map((url) => summarizeUrl(url))
    .filter((item) => item.domain);

  const findingLabels = (ruleResult?.findings || [])
    .map((finding) => ({ severity: finding.severity, label: finding.label }))
    .slice(0, 12);

  const severityCounts = countSeverities(ruleResult?.findings || []);

  return {
    version: 1,
    mode,
    sender_domain: senderDomain || null,
    reply_to_domain: replyToDomain || null,
    reply_to_mismatch: Boolean(senderDomain && replyToDomain && senderDomain !== replyToDomain),
    claimed_brand: claimedBrand,
    received_hops: receivedHops,
    urls: urlSummaries,
    rule_score: ruleResult?.score ?? null,
    rule_risk: ruleResult?.risk ?? null,
    rule_finding_counts: severityCounts,
    rule_finding_labels: findingLabels
  };
}

function normalizeOptionalInt(value) {
  if (value === "" || value === undefined || value === null) return null;
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return null;
  return Math.max(0, Math.min(999, Math.trunc(parsed)));
}

function summarizeUrl(url) {
  const domain = getDomain(url);
  if (!domain) return { domain: null, flags: [] };
  const flags = [];

  if (String(url).toLowerCase().startsWith("http://")) flags.push("http");
  if (shorteners.includes(domain)) flags.push("shortener");
  if (isIpHost(domain)) flags.push("ip_host");
  if (domain.startsWith("xn--") || domain.includes(".xn--")) flags.push("punycode");
  if (domain.split(".").length >= 5) flags.push("many_subdomains");
  if (isSuspiciousDomain(domain)) flags.push("suspicious_domain");

  return { domain, flags };
}

function countSeverities(findings) {
  return findings.reduce(
    (acc, finding) => {
      if (finding?.severity === "high") acc.high += 1;
      if (finding?.severity === "medium") acc.medium += 1;
      if (finding?.severity === "low") acc.low += 1;
      return acc;
    },
    { high: 0, medium: 0, low: 0 }
  );
}

function isHttpContext() {
  if (typeof window === "undefined") return false;
  const protocol = window.location?.protocol;
  return protocol === "http:" || protocol === "https:";
}

function isValidLlmSummary(value) {
  if (!value || typeof value !== "object") return false;
  if (!["low", "medium", "high"].includes(value.verdict)) return false;
  if (typeof value.confidence !== "number" || !Number.isFinite(value.confidence)) return false;
  if (!Array.isArray(value.reasons)) return false;
  return true;
}

function llmVerdictToScoreBand(verdict) {
  if (verdict === "high") return 85;
  if (verdict === "medium") return 55;
  return 20;
}

function clampScore(value) {
  return Math.max(0, Math.min(100, value));
}


function scoreReceivedHops(value, findings, passedChecks) {
  if (value === "" || value === undefined || value === null) return 0;
  const hops = Number(value);
  if (!Number.isFinite(hops)) return 0;
  if (hops === 0) {
    findings.push({
      severity: "medium",
      label: "Missing received-chain data",
      detail: "A normal email usually includes at least one Received header."
    });
    return 10;
  }
  if (hops > 8) {
    findings.push({
      severity: "low",
      label: "Long received chain",
      detail: `${hops} relay hops can indicate forwarding or unusual routing.`
    });
    return 6;
  }
  passedChecks.push("Received-hop count is within a typical range.");
  return 0;
}

function scoreUrl(url, findings) {
  const domain = getDomain(url);
  if (!domain) return 0;
  let score = 0;

  if (shorteners.includes(domain)) {
    score += 14;
    findings.push({
      severity: "medium",
      label: "Shortened link hides destination",
      detail: `${domain} may obscure the real target.`
    });
  }

  if (isIpHost(domain)) {
    score += 18;
    findings.push({
      severity: "high",
      label: "Link uses raw IP address",
      detail: `The URL points to ${domain} instead of a named domain.`
    });
  }

  if (domain.startsWith("xn--") || domain.includes(".xn--")) {
    score += 18;
    findings.push({
      severity: "high",
      label: "Possible homograph domain",
      detail: `${domain} uses punycode, which can hide lookalike characters.`
    });
  }

  if (domain.split(".").length >= 5) {
    score += 8;
    findings.push({
      severity: "low",
      label: "Excessive subdomains",
      detail: `${domain} has a long subdomain chain.`
    });
  }

  if (isSuspiciousDomain(domain)) {
    score += 12;
    findings.push({
      severity: "medium",
      label: "Suspicious link domain",
      detail: `Link points to ${domain}.`
    });
  }

  if (url.startsWith("http://")) {
    score += 9;
    findings.push({
      severity: "low",
      label: "Unencrypted link",
      detail: "The email contains an HTTP link instead of HTTPS."
    });
  }

  return score;
}

function getDomain(value) {
  if (!value) return "";
  const cleaned = String(value).trim().toLowerCase();
  const emailMatch = cleaned.match(/@([a-z0-9.-]+\.[a-z]{2,}|\d{1,3}(?:\.\d{1,3}){3})/i);
  if (emailMatch) return normalizeDomain(emailMatch[1]);
  try {
    const url = cleaned.startsWith("http") ? new URL(cleaned) : new URL(`https://${cleaned}`);
    return normalizeDomain(url.hostname);
  } catch {
    const domainMatch = cleaned.match(/\b(([a-z0-9-]+\.)+[a-z]{2,}|\d{1,3}(?:\.\d{1,3}){3})\b/i);
    return domainMatch ? normalizeDomain(domainMatch[0]) : "";
  }
}

function normalizeDomain(domain) {
  return domain.replace(/^www\./, "").replace(/[.,;:]+$/, "");
}

function extractUrls(text) {
  return text.match(/https?:\/\/[^\s<>"')]+/gi) || [];
}

function isIpHost(domain) {
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(domain);
}

function isSuspiciousDomain(domain) {
  const parts = domain.split(".");
  const tld = parts[parts.length - 1];
  return suspiciousTlds.includes(tld) || /secure|verify|login|account|reset|alert|wallet|support/.test(domain);
}

function checkBrandImpersonation(brand, senderDomain, urls) {
  if (!brand || !senderDomain) return null;
  const key = brand.trim().toLowerCase();
  const trusted = trustedDomains[key];
  if (!trusted) return null;
  const allDomains = [senderDomain, ...urls.map(getDomain).filter(Boolean)];
  const hasTrustedDomain = allDomains.some((domain) => trusted.some((trustedDomain) => domain === trustedDomain || domain.endsWith(`.${trustedDomain}`)));
  if (!hasTrustedDomain) {
    return {
      severity: "high",
      weight: 22,
      label: "Possible brand impersonation",
      detail: `Claims ${brand}, but sender/link domains do not match known trusted domains.`
    };
  }
  return null;
}

function classifyRisk(score, profile = modeProfiles.balanced) {
  if (score >= 71) return "High";
  if (score >= profile.mediumThreshold) return "Medium";
  return "Low";
}

function buildExplanation(score, risk, findings) {
  if (!findings.length) {
    return "No strong phishing indicators were found. The message still should be handled carefully if it came from an unexpected sender.";
  }
  const highCount = findings.filter((finding) => finding.severity === "high").length;
  const mediumCount = findings.filter((finding) => finding.severity === "medium").length;
  return `The message is classified as ${risk.toLowerCase()} risk with a score of ${score}/100. The strongest evidence includes ${highCount} high-severity and ${mediumCount} medium-severity indicators, especially ${findings.slice(0, 3).map((finding) => finding.label.toLowerCase()).join(", ")}.`;
}

function buildReport(email, score, risk, findings, passedChecks, profile = modeProfiles.balanced) {
  const recommendation = score >= profile.phishingThreshold
    ? "Do not click links or provide data. Verify through a known trusted channel and escalate to security."
    : "No immediate blocking signal was found. Continue normal verification if the message was unexpected.";
  const evidence = findings.length
    ? findings.map((finding) => `- ${finding.label}: ${finding.detail}`).join("\n")
    : "- No strong suspicious indicators detected.";
  const passed = passedChecks.length
    ? dedupeStrings(passedChecks).map((check) => `- ${check}`).join("\n")
    : "- No positive checks available.";

  return [
    "PhishGuard Email Triage Report",
    `Subject: ${email.subject || "(none)"}`,
    `Sender: ${email.sender || "(unknown)"}`,
    `Risk: ${risk} (${score}/100)`,
    `Recommendation: ${recommendation}`,
    "",
    "Suspicious evidence:",
    evidence,
    "",
    "Passed checks:",
    passed
  ].join("\n");
}

function dedupeFindings(findings) {
  const seen = new Set();
  return findings.filter((finding) => {
    const key = `${finding.label}:${finding.detail}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function dedupeStrings(values) {
  return [...new Set(values)];
}

function evaluateSamples(samples, mode = "balanced") {
  let tp = 0;
  let tn = 0;
  let fp = 0;
  let fn = 0;

  samples.forEach((sample) => {
    const result = analyzeEmail({ ...sample, mode });
    const expectedPhishing = sample.expected === "phishing";
    if (result.phishing && expectedPhishing) tp += 1;
    if (!result.phishing && !expectedPhishing) tn += 1;
    if (result.phishing && !expectedPhishing) fp += 1;
    if (!result.phishing && expectedPhishing) fn += 1;
  });

  const total = samples.length || 1;
  const accuracy = (tp + tn) / total;
  const precision = tp + fp === 0 ? 0 : tp / (tp + fp);
  const recall = tp + fn === 0 ? 0 : tp / (tp + fn);

  return { accuracy, precision, recall, truePositives: tp, trueNegatives: tn, falsePositives: fp, falseNegatives: fn, total };
}
