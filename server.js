const express = require("express");
require("dotenv").config();

const app = express();
app.use(express.json({ limit: "200kb" }));

app.use(express.static(__dirname, { dotfiles: "ignore" }));

app.post("/api/analyze-llm", async (req, res) => {
  const apiKey = process.env.OPENAI_API_KEY;
  if (!apiKey) {
    return res.status(503).json({ error: "OPENAI_API_KEY is not set on the server." });
  }

  const summary = req.body?.summary;
  if (!summary || typeof summary !== "object") {
    return res.status(400).json({ error: "Missing or invalid `summary` object." });
  }

  try {
    const result = await analyzeWithOpenAI(summary, apiKey, process.env.OPENAI_MODEL || "gpt-4o-mini");
    return res.json(result);
  } catch (error) {
    console.error("LLM analyze failed:", error?.message || error);
    return res.status(502).json({ error: "LLM analyze failed." });
  }
});

const port = Number(process.env.PORT) || 3000;
app.listen(port, () => {
  console.log(`PhishGuard server running at http://localhost:${port}`);
});

async function analyzeWithOpenAI(summary, apiKey, model) {
  const system = [
    "You are PhishGuard's LLM assistant for email phishing triage.",
    "You will receive ONLY a structured preprocessing summary (no raw subject/body).",
    "Return a JSON object that matches the provided schema exactly.",
    "Be concise and focus on actionable security guidance."
  ].join(" ");

  const user = `Preprocessing summary (JSON):\n${JSON.stringify(summary, null, 2)}`;

  const payload = {
    model,
    input: [
      { role: "system", content: system },
      { role: "user", content: user }
    ],
    max_output_tokens: 700,
    text: {
      format: {
        type: "json_schema",
        name: "phishguard_llm_summary",
        schema: phishguardSummarySchema(),
        strict: true
      }
    }
  };

  const response = await fetch("https://api.openai.com/v1/responses", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${apiKey}`
    },
    body: JSON.stringify(payload)
  });

  if (!response.ok) {
    const text = await response.text().catch(() => "");
    throw new Error(`OpenAI API error (${response.status}): ${text.slice(0, 500)}`);
  }

  const data = await response.json();
  const { outputText, refusal } = extractOutputTextOrRefusal(data);
  if (refusal) throw new Error(`Model refusal: ${refusal}`);
  if (!outputText) throw new Error("No output_text found in OpenAI response.");

  let parsed;
  try {
    parsed = JSON.parse(outputText);
  } catch (error) {
    throw new Error(`Failed to parse assistant JSON: ${error?.message || error}`);
  }

  if (!isValidAssistantSummary(parsed)) {
    throw new Error("Assistant returned JSON but it did not match the expected shape.");
  }

  return parsed;
}

function extractOutputTextOrRefusal(response) {
  if (typeof response?.refusal === "string" && response.refusal) {
    return { outputText: "", refusal: response.refusal };
  }

  if (typeof response?.output_text === "string" && response.output_text) {
    return { outputText: response.output_text, refusal: "" };
  }

  const output = Array.isArray(response?.output) ? response.output : [];
  for (const item of output) {
    if (item?.type !== "message") continue;
    const content = Array.isArray(item?.content) ? item.content : [];
    for (const part of content) {
      if (part?.type === "refusal" && typeof part?.refusal === "string") {
        return { outputText: "", refusal: part.refusal };
      }
      if (part?.type === "output_text" && typeof part?.text === "string") {
        return { outputText: part.text, refusal: "" };
      }
    }
  }
  return { outputText: "", refusal: "" };
}

function isValidAssistantSummary(value) {
  if (!value || typeof value !== "object") return false;
  if (!["low", "medium", "high"].includes(value.verdict)) return false;
  if (typeof value.confidence !== "number" || !Number.isFinite(value.confidence)) return false;
  if (!Array.isArray(value.reasons)) return false;
  if (typeof value.summary !== "string") return false;
  if (typeof value.likely_goal !== "string") return false;
  if (!Array.isArray(value.recommended_actions)) return false;
  if (!["ignore", "verify", "escalate"].includes(value.user_action)) return false;
  return true;
}

function phishguardSummarySchema() {
  return {
    type: "object",
    properties: {
      verdict: { type: "string", enum: ["low", "medium", "high"] },
      confidence: { type: "number" },
      summary: { type: "string" },
      likely_goal: {
        type: "string",
        enum: ["credential_theft", "payment_fraud", "qr_phishing", "malware_delivery", "unknown"]
      },
      reasons: { type: "array", items: { type: "string" } },
      signals: {
        type: "array",
        items: {
          type: "object",
          properties: {
            severity: { type: "string", enum: ["low", "medium", "high"] },
            reason: { type: "string" }
          },
          required: ["severity", "reason"],
          additionalProperties: false
        }
      },
      urls: {
        type: "array",
        items: {
          type: "object",
          properties: {
            domain: {
              anyOf: [{ type: "string" }, { type: "null" }]
            },
            risk: { type: "string", enum: ["low", "medium", "high"] },
            flags: { type: "array", items: { type: "string" } }
          },
          required: ["domain", "risk", "flags"],
          additionalProperties: false
        }
      },
      suspicious_elements: {
        type: "object",
        properties: {
          sender_domain: { anyOf: [{ type: "string" }, { type: "null" }] },
          reply_to_domain: { anyOf: [{ type: "string" }, { type: "null" }] },
          claimed_brand: { anyOf: [{ type: "string" }, { type: "null" }] },
          url_count: { type: "integer" }
        },
        required: ["sender_domain", "reply_to_domain", "claimed_brand", "url_count"],
        additionalProperties: false
      },
      recommended_actions: { type: "array", items: { type: "string" } },
      user_action: { type: "string", enum: ["ignore", "verify", "escalate"] }
    },
    required: [
      "verdict",
      "confidence",
      "summary",
      "likely_goal",
      "reasons",
      "signals",
      "urls",
      "suspicious_elements",
      "recommended_actions",
      "user_action"
    ],
    additionalProperties: false
  };
}
