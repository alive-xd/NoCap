/**
 * HomographAnalyzer v1.0
 *
 * Applies judgment to HomographParser Evidence to detect brand impersonation.
 * Input: Evidence extracted by HomographParser.
 *
 * Threshold: distanceFlag = 2
 * Rationale: A Levenshtein distance of 1-2 on a brand-length string is
 * extremely suspicious. Most legitimate domain variants of major brands
 * are registered by the brand itself. Distance of 2 allows for one
 * character substitution plus one insertion/deletion, covering:
 *   - "paypa1.com" (distance 1 from "paypal")
 *   - "payrnent.com" (distance 1 from "payment" after normalization)
 *   - "microsofft.com" (distance 1 from "microsoft")
 *   Distance of 3 is used as an extended check with lower confidence.
 */

import type {
  Analyzer,
  AnalyzerConfig,
  AnalyzerInput,
  ProducedFinding,
} from "@/lib/pipeline/types";

const config: AnalyzerConfig = {
  name: "HomographAnalyzer",
  version: "1.0",
  enabled: true,
  thresholds: {
    distanceFlag: 2,        // distance <= 2: HIGH confidence Finding
    extendedDistanceFlag: 3, // distance == 3: MEDIUM confidence Finding
  },
};

function getFactValue<T>(evidence: AnalyzerInput["evidence"], factType: string): T | null {
  const e = evidence.find((ev) => ev.fact_type === factType);
  return e ? (e.fact_value as T) : null;
}

function getEvidenceIds(evidence: AnalyzerInput["evidence"], ...factTypes: string[]): string[] {
  return evidence
    .filter((ev) => factTypes.includes(ev.fact_type))
    .map((ev) => ev.id);
}

export class HomographAnalyzer implements Analyzer {
  readonly config = config;

  analyze(input: AnalyzerInput): ProducedFinding[] {
    if (!config.enabled) return [];

    const { thresholds } = config;

    const closestDistance = getFactValue<number>(input.evidence, "closest_distance");
    if (closestDistance === null || closestDistance > thresholds.extendedDistanceFlag) {
      return [];
    }

    const closestBrand = getFactValue<string>(input.evidence, "closest_brand") ?? "unknown";
    const inputDomain = getFactValue<string>(input.evidence, "input_domain") ?? "";
    const inputSLD = getFactValue<string>(input.evidence, "input_sld") ?? "";

    const isHighConfidence = closestDistance <= thresholds.distanceFlag;

    return [
      {
        claim: "Potential Brand Impersonation",
        severity: isHighConfidence ? "HIGH" : "MEDIUM",
        confidence_score: isHighConfidence ? 80 : 55,
        score_contribution: isHighConfidence ? 20 : 10,
        reasoning: `Domain "${inputDomain}" (SLD: "${inputSLD}") has a Levenshtein distance of ${closestDistance} from brand "${closestBrand}". This falls within the threshold for visual impersonation (distance <= ${thresholds.distanceFlag}). Homograph normalization (rn→m, 0→o, etc.) was applied before comparison to detect character-substitution attacks.`,
        attack_techniques: ['T1566'],
        evidence_ids: getEvidenceIds(
          input.evidence,
          "closest_brand",
          "closest_distance",
          "input_domain",
          "input_sld",
          "all_candidates"
        ),
      },
    ];
  }
}
