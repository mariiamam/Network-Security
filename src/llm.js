const mockShorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "rebrand.ly", "cutt.ly"];
const mockFreeMail = ["gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "proton.me", "temporarymail.com"];
const mockSuspiciousTlds = ["ru", "cn", "xyz", "top", "click", "zip", "mov", "tk", "icu", "rest", "support"];

async function realLlmSummarizeEmail(preprocessSummary) {
  const response = await fetch("/api/analyze-llm", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ summary: preprocessSummary })
  });

  if (!response.ok) {
    const text = await response.text().catch(() => "");
    throw new Error(`Backend error (${response.status}): ${text.slice(0, 300)}`);
  }

  return response.json();
}

async function mockLlmSummarizeEmail(email) {
  const subject = String(email?.subject || "");
  const body = String(email?.body || "");
  const text = `${subject}\n${body}`;
  const claimedBrand = String(email?.claimedBrand || "").trim() || null;

  const urls = typeof extractUrls === "function" ? extractUrls(text) : extractUrlsFallback(text);
  const senderDomain = typeof getDomain === "function" ? getDomain(email?.sender) : "";
  const replyDomain = typeof getDomain === "function" ? getDomain(email?.replyTo) : "";

  const urlAssessments = urls.map(assessUrl);
  const signals = [];

  addIfMatch(signals, text, /\b(password|username|login|one-time code|otp|verification code|card number|payment details|ssn|social security|seed phrase)\b/i, "high", "Credential or sensitive-data request");
  addIfMatch(signals, text, /\b(wire transfer|bank details|invoice attached|remittance|past due|payment)\b/i, "medium", "Payment or invoice pressure");
  addIfMatch(signals, text, /\b(suspended|locked|terminated|unauthorized|mailbox will be closed|account will be closed)\b/i, "high", "Threat of suspension or loss");
  addIfMatch(signals, text, /\b(urgent|immediately|final warning|last chance|action required|today|within\s+\d+\s*(minutes|hours))\b/i, "medium", "Urgency / pressure language");
  addIfMatch(signals, text, /\b(dear customer|dear user|valued customer)\b/i, "low", "Generic greeting");
  addIfMatch(signals, text, /\b(scan the qr|qr code|use your phone camera)\b/i, "medium", "QR-code phishing cue");
  addIfMatch(signals, text, /\b(do not call|don't call|keep this confidential)\b/i, "medium", "BEC-style secrecy / isolation request");

  if (senderDomain && replyDomain && senderDomain !== replyDomain) {
    signals.push({ severity: "medium", reason: "Reply-to domain differs from sender domain." });
  }

  if (claimedBrand && senderDomain && mockFreeMail.includes(senderDomain)) {
    signals.push({ severity: "medium", reason: "Claims a brand but sender uses a free-mail domain." });
  }

  urlAssessments.forEach((assessment) => {
    if (assessment.risk === "high") signals.push({ severity: "high", reason: `High-risk link pattern: ${assessment.domain || "unknown host"}.` });
    if (assessment.risk === "medium") signals.push({ severity: "medium", reason: `Suspicious link characteristics: ${assessment.domain || "unknown host"}.` });
    if (assessment.risk === "low") signals.push({ severity: "low", reason: `Link may be lower-trust: ${assessment.domain || "unknown host"}.` });
  });

  if (urls.length === 0 && text.trim()) {
    signals.push({ severity: "low", reason: "No direct links found; relies mostly on social engineering cues." });
  }

  const likelyGoal = inferLikelyGoal(text);
  const verdict = inferVerdict(signals);
  const confidence = inferConfidence(verdict, signals);
  const reasons = signals.map((signal) => signal.reason).slice(0, 6);

  return {
    verdict,
    confidence,
    summary: buildSummary(verdict, likelyGoal, reasons),
    likely_goal: likelyGoal,
    reasons,
    signals,
    urls: urlAssessments,
    suspicious_elements: {
      sender_domain: senderDomain || null,
      reply_to_domain: replyDomain || null,
      claimed_brand: claimedBrand,
      url_count: urls.length
    },
    recommended_actions: recommendedActionsForVerdict(verdict),
    user_action: verdict === "high" ? "escalate" : verdict === "medium" ? "verify" : "ignore"
  };
}

function extractUrlsFallback(text) {
  return String(text).match(/https?:\/\/[^\s<>"')]+/gi) || [];
}

function addIfMatch(signals, text, regex, severity, reason) {
  if (regex.test(text)) signals.push({ severity, reason });
}

function assessUrl(url) {
  const domain = typeof getDomain === "function" ? getDomain(url) : "";
  const flags = [];
  const normalizedUrl = String(url || "");

  if (normalizedUrl.toLowerCase().startsWith("http://")) flags.push("http");
  if (domain && mockShorteners.includes(domain)) flags.push("shortener");
  if (domain && isIpLike(domain)) flags.push("ip_host");
  if (domain && (domain.startsWith("xn--") || domain.includes(".xn--"))) flags.push("punycode");
  if (domain && domain.split(".").length >= 5) flags.push("many_subdomains");
  if (domain && /secure|verify|login|account|reset|alert|wallet|support/.test(domain)) flags.push("suspicious_keywords");
  if (domain && mockSuspiciousTlds.includes(domain.split(".").slice(-1)[0])) flags.push("suspicious_tld");

  const risk = flags.includes("ip_host") || flags.includes("punycode")
    ? "high"
    : flags.includes("shortener") || flags.includes("suspicious_tld") || flags.includes("suspicious_keywords")
      ? "medium"
      : flags.length
        ? "low"
        : "low";

  return { domain: domain || null, risk, flags };
}

function isIpLike(value) {
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(String(value));
}

function inferLikelyGoal(text) {
  const value = String(text || "");
  if (/\b(password|username|login|otp|verification code|seed phrase)\b/i.test(value)) return "credential_theft";
  if (/\b(wire transfer|bank details|invoice|remittance|payment)\b/i.test(value)) return "payment_fraud";
  if (/\b(qr code|scan the qr)\b/i.test(value)) return "qr_phishing";
  if (/\b(attachment|pdf|doc|document)\b/i.test(value)) return "malware_delivery";
  return "unknown";
}

function inferVerdict(signals) {
  const high = signals.filter((signal) => signal.severity === "high").length;
  const medium = signals.filter((signal) => signal.severity === "medium").length;
  if (high >= 1) return "high";
  if (medium >= 2) return "high";
  if (medium === 1 || signals.length >= 3) return "medium";
  return signals.length ? "low" : "low";
}

function inferConfidence(verdict, signals) {
  const counts = signals.reduce((acc, signal) => {
    acc[signal.severity] = (acc[signal.severity] || 0) + 1;
    return acc;
  }, {});

  const base = verdict === "high" ? 0.78 : verdict === "medium" ? 0.58 : 0.36;
  const bump = (counts.high || 0) * 0.06 + (counts.medium || 0) * 0.04 + (counts.low || 0) * 0.02;
  return Math.min(0.95, Math.max(0.25, Number((base + bump).toFixed(2))));
}

function buildSummary(verdict, goal, reasons) {
  const top = reasons[0] ? `Key signal: ${reasons[0]}` : "No strong indicators detected.";
  return `${verdict.toUpperCase()} risk (${goal.replace("_", " ")}). ${top}`;
}

function recommendedActionsForVerdict(verdict) {
  if (verdict === "high") {
    return [
      "Do not click links or provide credentials.",
      "Verify using an official website/phone number (not from the email).",
      "Report/escalate to your security team."
    ];
  }
  if (verdict === "medium") {
    return [
      "Avoid clicking links until verified.",
      "Verify the sender and link destination independently.",
      "Report if you cannot confirm legitimacy."
    ];
  }
  return [
    "No strong indicators found, but stay cautious with unexpected emails.",
    "Verify unusual requests through a trusted channel."
  ];
}
