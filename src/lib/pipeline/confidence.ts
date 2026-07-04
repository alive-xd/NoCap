/**
 * Confidence — derives a human-readable label from a numeric score.
 *
 * The numeric score (0-100) is the stored source of truth.
 * The label is NEVER stored — always derived at read time.
 *
 * Thresholds:
 *   High:   score >= 75
 *   Medium: score >= 40
 *   Low:    score < 40
 */

import type { ConfidenceLabel } from "./types";

export function confidenceLabel(score: number): ConfidenceLabel {
  if (score >= 75) return "High";
  if (score >= 40) return "Medium";
  return "Low";
}

/**
 * Clamps a score to 0-100 range.
 */
export function clampScore(score: number): number {
  return Math.max(0, Math.min(100, Math.round(score)));
}

/**
 * Returns a CSS class name corresponding to the confidence label,
 * using the design system tokens defined in globals.css.
 */
export function confidenceClass(score: number): string {
  const label = confidenceLabel(score);
  switch (label) {
    case "High":
      return "text-accent-confirmed";
    case "Medium":
      return "text-accent-open";
    case "Low":
      return "text-accent-severe";
  }
}
