/**
 * Score computation
 *
 * Computes the final investigation score from all Findings under a
 * given Scoring Profile version.
 *
 * The score is a weighted sum of each Finding's score_contribution,
 * clamped to 0-100. The weights at this stage are already baked into
 * score_contribution when Analyzers produce their Findings — the scoring
 * profile's source_weights document the intended allocation but the actual
 * arithmetic happens in Analyzers.
 *
 * This function's job: sum, clamp, and return. No re-weighting.
 *
 * Partial failure degradation:
 *   If some sources failed, reduce the final score proportionally to
 *   reflect reduced confidence in the score's completeness.
 *   Degradation factor = (successful_sources / total_sources)^0.5
 *   (square root to avoid over-penalizing single-source failures)
 */

import type { Finding, ScoringProfile } from "@/lib/pipeline/types";

export interface ScoreResult {
  finalScore: number;
  rawSum: number;
  degradationFactor: number;
  breakdown: ScoreLineItem[];
}

interface ScoreLineItem {
  claim: string;
  generatedBy: string;
  contribution: number;
  severity: string;
}

export function computeScore(
  findings: Finding[],
  _profile: ScoringProfile, // reserved for future re-weighting
  successfulSources: number,
  totalSources: number
): ScoreResult {
  const seen = new Set<string>();
  const breakdown: ScoreLineItem[] = [];
  let rawSum = 0;

  for (const finding of findings) {
    const key = `${finding.generated_by}:${finding.claim}`;
    if (seen.has(key)) continue;
    seen.add(key);

    rawSum += finding.score_contribution;
    breakdown.push({
      claim: finding.claim,
      generatedBy: finding.generated_by,
      contribution: finding.score_contribution,
      severity: finding.severity,
    });
  }

  // Clamp before degradation
  const clampedRaw = Math.min(100, Math.max(0, rawSum));

  // Partial failure degradation
  const degradationFactor =
    totalSources > 0
      ? Math.sqrt(successfulSources / totalSources)
      : 1;

  const finalScore = Math.round(clampedRaw * degradationFactor);

  return {
    finalScore,
    rawSum,
    degradationFactor,
    breakdown,
  };
}
