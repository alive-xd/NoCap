import React from "react";
import type { Finding } from "@/lib/pipeline/types";

interface RadarChartProps {
  findings: Finding[];
}

const CATEGORIES = {
  INFRASTRUCTURE: "Infrastructure",
  MALWARE_REPUTATION: "Malware & Rep.",
  PHISHING_EMAIL: "Phishing/Email",
};

// Map each analyzer to one of the three categories
const ANALYZER_MAPPING: Record<string, string> = {
  VirusTotalAnalyzer: CATEGORIES.MALWARE_REPUTATION,
  AbuseIPDBAnalyzer: CATEGORIES.MALWARE_REPUTATION,
  ASNReputationAnalyzer: CATEGORIES.MALWARE_REPUTATION,
  DomainAgeAnalyzer: CATEGORIES.INFRASTRUCTURE,
  EntropyAnalyzer: CATEGORIES.INFRASTRUCTURE,
  FingerprintAnalyzer: CATEGORIES.INFRASTRUCTURE,
  CVEPriorityAnalyzer: CATEGORIES.INFRASTRUCTURE,
  HomographAnalyzer: CATEGORIES.PHISHING_EMAIL,
  EmailAuthAnalyzer: CATEGORIES.PHISHING_EMAIL,
};

const CATEGORY_KEYS = [
  CATEGORIES.INFRASTRUCTURE,
  CATEGORIES.MALWARE_REPUTATION,
  CATEGORIES.PHISHING_EMAIL,
];

export default function RadarChart({ findings }: RadarChartProps) {
  // Aggregate scores and track whether a category was analyzed at all
  const scores = CATEGORY_KEYS.reduce((acc, cat) => {
    acc[cat] = { sum: 0, count: 0 };
    return acc;
  }, {} as Record<string, { sum: number; count: number }>);

  for (const f of findings) {
    const cat = ANALYZER_MAPPING[f.generated_by];
    if (cat && scores[cat]) {
      scores[cat].sum += f.score_contribution;
      scores[cat].count += 1;
    }
  }

  // Chart Dimensions
  const size = 320;
  const center = size / 2;
  const radius = 90;

  // Compute points for a given percentage (0-100)
  const getPoint = (index: number, total: number, value: number, r: number) => {
    const angle = (Math.PI * 2 * index) / total - Math.PI / 2;
    const distance = (value / 100) * r;
    return {
      x: center + Math.cos(angle) * distance,
      y: center + Math.sin(angle) * distance,
    };
  };

  // Generate Data Polygon Points
  const dataPoints = CATEGORY_KEYS.map((cat, i) => {
    const isAnalyzed = scores[cat].count > 0;
    // If analyzed, use clamped sum (max 100). If not, force 0.
    const val = isAnalyzed ? Math.min(100, Math.max(0, scores[cat].sum)) : 0;
    return { ...getPoint(i, CATEGORY_KEYS.length, val, radius), isAnalyzed, val };
  });

  const dataPolygon = dataPoints.map(p => `${p.x},${p.y}`).join(" ");
  const gridLevels = [25, 50, 75, 100];

  return (
    <div style={{ display: "flex", justifyContent: "center", alignItems: "center", width: "100%", padding: "1rem" }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        
        {/* Grid Rings */}
        {gridLevels.map((level) => {
          const pts = CATEGORY_KEYS.map((_, i) => getPoint(i, CATEGORY_KEYS.length, level, radius));
          return (
            <polygon
              key={level}
              points={pts.map(p => `${p.x},${p.y}`).join(" ")}
              fill="none"
              stroke="var(--bg-border)"
              strokeWidth="1"
              strokeDasharray={level < 100 ? "4 4" : "none"}
            />
          );
        })}

        {/* Axes (Spokes) */}
        {CATEGORY_KEYS.map((cat, i) => {
          const outerPoint = getPoint(i, CATEGORY_KEYS.length, 100, radius);
          const isAnalyzed = scores[cat].count > 0;
          return (
            <line
              key={i}
              x1={center}
              y1={center}
              x2={outerPoint.x}
              y2={outerPoint.y}
              // Muted/dashed if not analyzed
              stroke={isAnalyzed ? "var(--bg-border)" : "var(--bg-border)"}
              strokeWidth="1"
              strokeDasharray={isAnalyzed ? "none" : "6 6"}
              style={{ opacity: isAnalyzed ? 1 : 0.3 }}
            />
          );
        })}

        {/* Data Polygon */}
        <polygon
          points={dataPolygon}
          fill="color-mix(in srgb, var(--accent-primary) 20%, transparent)"
          stroke="var(--accent-primary)"
          strokeWidth="2"
        />

        {/* Data Points (Dots at vertices) */}
        {dataPoints.map((p, i) => {
          // Do not draw a prominent dot for "Not Analyzed" (which is at the center)
          if (!p.isAnalyzed) return null;
          return (
            <circle
              key={`dot-${i}`}
              cx={p.x}
              cy={p.y}
              r="4"
              fill="var(--bg-base)"
              stroke="var(--accent-primary)"
              strokeWidth="2"
            />
          );
        })}

        {/* Labels & "Not Analyzed" Badge */}
        {CATEGORY_KEYS.map((cat, i) => {
          const labelPoint = getPoint(i, CATEGORY_KEYS.length, 135, radius); // Push text out
          const isAnalyzed = scores[cat].count > 0;
          
          return (
            <g key={`label-${cat}`}>
              <text
                x={labelPoint.x}
                y={labelPoint.y + 2} // Align vertically
                textAnchor="middle"
                fill={isAnalyzed ? "var(--text-secondary)" : "var(--text-tertiary)"}
                fontSize="11"
                fontFamily="var(--font-mono)"
                letterSpacing="0.05em"
                style={{ opacity: isAnalyzed ? 1 : 0.5 }}
              >
                {cat}
              </text>
              {!isAnalyzed && (
                <text
                  x={labelPoint.x}
                  y={labelPoint.y + 16} // Right under the main label
                  textAnchor="middle"
                  fill="var(--text-tertiary)"
                  fontSize="9"
                  fontFamily="var(--font-mono)"
                  letterSpacing="0.05em"
                  style={{ opacity: 0.4 }}
                >
                  (Not Analyzed)
                </text>
              )}
            </g>
          );
        })}
      </svg>
    </div>
  );
}
