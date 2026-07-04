/**
 * OpenRouter API client — used exclusively for Investigation Summary generation.
 *
 * OpenRouter is a unified API gateway supporting multiple models.
 * Used ONLY for the CVE Watch Investigation Summary section.
 * Labeled as "Investigation Summary" in the UI.
 *
 * Signup: https://openrouter.ai/keys
 * Docs: https://openrouter.ai/docs
 */

const OPENROUTER_BASE = "https://openrouter.ai/api/v1";

// Use a cost-effective model for structured summaries
const DEFAULT_MODEL = "google/gemini-flash-1.5";

export interface SummaryRequest {
  investigationType: string;
  target: string;
  findings: Array<{
    claim: string;
    severity: string;
    confidence_score: number;
    reasoning: string | null;
  }>;
  finalScore: number;
}

/**
 * Generates a data-grounded investigation summary from structured Findings.
 * Returns a plain-text paragraph — not markdown, not chatbot-style prose.
 */
export async function generateInvestigationSummary(
  request: SummaryRequest
): Promise<string> {
  const apiKey = process.env.OPENROUTER_API_KEY;
  if (!apiKey) {
    return "Investigation Summary unavailable — OPENROUTER_API_KEY not configured.";
  }

  const findingsList = request.findings
    .map(
      (f) =>
        `- ${f.claim} (Severity: ${f.severity}, Confidence: ${f.confidence_score}): ${f.reasoning ?? "no reasoning recorded"}`
    )
    .join("\n");

  const prompt = `You are generating a concise, factual investigation summary for a threat intelligence report. Write 2-4 sentences in neutral, professional prose. Reference specific findings and their severity. Do not use markdown. Do not use conversational filler or greetings. Do not add recommendations unless they are directly supported by the findings.

Investigation type: ${request.investigationType}
Target: ${request.target}
NoCap Score: ${request.finalScore}/100

Findings:
${findingsList}

Write the investigation summary:`;

  const response = await fetch(`${OPENROUTER_BASE}/chat/completions`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
      "HTTP-Referer": "https://nocap.app",
      "X-Title": "NoCap Threat Intelligence",
    },
    body: JSON.stringify({
      model: DEFAULT_MODEL,
      messages: [{ role: "user", content: prompt }],
      max_tokens: 300,
      temperature: 0.2,
    }),
    cache: "no-store",
  });

  if (!response.ok) {
    const errorText = await response.text().catch(() => response.statusText);
    throw new Error(`OpenRouter error ${response.status}: ${errorText}`);
  }

  const data = (await response.json()) as {
    choices: Array<{ message: { content: string } }>;
  };

  return data.choices[0]?.message?.content?.trim() ?? "Summary generation failed.";
}
