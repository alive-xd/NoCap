"use client";

import React, { useState } from "react";
import type { InvestigationStatus } from "@/lib/pipeline/types";

// ─── Pipeline stage definitions ────────────────────────────────────────────
// Source of truth: the comment header in src/lib/pipeline/types.ts
//   Artifact → Parser → Evidence → Analyzer → Finding → Score

export const PIPELINE_STAGES = [
  {
    id: "artifact",
    label: "Artifact",
    description: "Raw API responses fetched concurrently from OSINT sources",
  },
  {
    id: "parser",
    label: "Parser",
    description: "Structured evidence extracted from each raw artifact",
  },
  {
    id: "evidence",
    label: "Evidence",
    description: "Typed, normalised facts stored against the investigation",
  },
  {
    id: "analyzer",
    label: "Analyzer",
    description: "Domain-specific rules applied to evidence bundles",
  },
  {
    id: "finding",
    label: "Finding",
    description: "Labelled claims with severity and confidence score",
  },
  {
    id: "score",
    label: "Score",
    description: "Weighted sum composited into a final risk score",
  },
] as const;

type StageId = (typeof PIPELINE_STAGES)[number]["id"];

// Map InvestigationStatus → the last stage that is considered active/reached
const STATUS_TO_ACTIVE_STAGE: Record<InvestigationStatus, StageId | null> = {
  CREATED: null,
  FETCHING_ARTIFACTS: "artifact",
  EXTRACTING_EVIDENCE: "evidence",
  RUNNING_ANALYZERS: "analyzer",
  SCORING: "finding",
  COMPLETED: "score",
  FAILED: null, // shown separately via prop
};

interface PipelineChainProps {
  /** "hero" = large, always-visible descriptions. "compact" = small dot strip. */
  size?: "hero" | "compact";
  /** Wire to a live investigation status to highlight stages reached. */
  activeStatus?: InvestigationStatus;
  /** If true, all stages after the active one are shown as "failed". */
  failed?: boolean;
  className?: string;
}

export default function PipelineChain({
  size = "hero",
  activeStatus,
  failed = false,
  className = "",
}: PipelineChainProps) {
  const [hoveredIdx, setHoveredIdx] = useState<number | null>(null);

  // Determine which stage index is currently active (inclusive)
  const activeStageId = activeStatus
    ? STATUS_TO_ACTIVE_STAGE[activeStatus]
    : null;
  const activeIdx = activeStageId
    ? PIPELINE_STAGES.findIndex((s) => s.id === activeStageId)
    : -1;

  function stageState(idx: number): "completed" | "active" | "failed" | "pending" {
    if (activeIdx === -1 && !failed) return "pending";
    if (failed && idx === activeIdx + 1) return "failed";
    if (idx <= activeIdx) return "completed";
    if (idx === activeIdx + 1 && !failed) return "active";
    return "pending";
  }

  if (size === "compact") {
    return (
      <div className={`pipeline-compact ${className}`} aria-label="Pipeline stages">
        {PIPELINE_STAGES.map((stage, idx) => {
          const state = stageState(idx);
          const isHovered = hoveredIdx === idx;
          return (
            <React.Fragment key={stage.id}>
              <div
                className={`pipeline-compact-node pipeline-node-${state}`}
                onMouseEnter={() => setHoveredIdx(idx)}
                onMouseLeave={() => setHoveredIdx(null)}
                aria-label={`${stage.label}: ${stage.description}`}
              >
                <div className="pipeline-compact-dot" />
                <span className="pipeline-compact-label">{stage.label}</span>
                {isHovered && (
                  <div className="pipeline-compact-tooltip" role="tooltip">
                    {stage.description}
                  </div>
                )}
              </div>
              {idx < PIPELINE_STAGES.length - 1 && (
                <div className={`pipeline-compact-arrow pipeline-arrow-${state}`} aria-hidden="true">
                  →
                </div>
              )}
            </React.Fragment>
          );
        })}
      </div>
    );
  }

  // Hero size
  return (
    <div className={`pipeline-hero ${className}`} role="list" aria-label="Investigation pipeline stages">
      {PIPELINE_STAGES.map((stage, idx) => {
        const state = stageState(idx);
        const isHovered = hoveredIdx === idx;
        return (
          <React.Fragment key={stage.id}>
            <div
              className={`pipeline-hero-stage pipeline-node-${state} ${isHovered ? "pipeline-hero-stage--hovered" : ""}`}
              role="listitem"
              onMouseEnter={() => setHoveredIdx(idx)}
              onMouseLeave={() => setHoveredIdx(null)}
            >
              <div className="pipeline-hero-node" aria-hidden="true">
                <span className="pipeline-hero-index">{String(idx + 1).padStart(2, "0")}</span>
              </div>
              <div className="pipeline-hero-label">{stage.label}</div>
              <div className="pipeline-hero-desc">{stage.description}</div>
            </div>
            {idx < PIPELINE_STAGES.length - 1 && (
              <div className={`pipeline-hero-connector pipeline-arrow-${state}`} aria-hidden="true" />
            )}
          </React.Fragment>
        );
      })}
    </div>
  );
}
