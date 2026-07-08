import { describe, it, expect } from "vitest";
import { confidenceLabel, clampScore, confidenceClass } from "../../pipeline/confidence";

describe("confidence", () => {
  describe("confidenceLabel", () => {
    it("returns High for scores >= 75", () => {
      expect(confidenceLabel(75)).toBe("High");
      expect(confidenceLabel(90)).toBe("High");
      expect(confidenceLabel(100)).toBe("High");
    });

    it("returns Medium for scores >= 40 and < 75", () => {
      expect(confidenceLabel(40)).toBe("Medium");
      expect(confidenceLabel(74)).toBe("Medium");
      expect(confidenceLabel(74.9)).toBe("Medium");
    });

    it("returns Low for scores < 40", () => {
      expect(confidenceLabel(0)).toBe("Low");
      expect(confidenceLabel(39)).toBe("Low");
      expect(confidenceLabel(39.9)).toBe("Low");
    });
  });

  describe("clampScore", () => {
    it("clamps and rounds scores to 0-100", () => {
      expect(clampScore(120)).toBe(100);
      expect(clampScore(-10)).toBe(0);
      expect(clampScore(50.4)).toBe(50);
      expect(clampScore(50.6)).toBe(51);
      expect(clampScore(100.1)).toBe(100);
    });
  });

  describe("confidenceClass", () => {
    it("returns the correct CSS class for each label", () => {
      expect(confidenceClass(80)).toBe("text-accent-confirmed"); // High
      expect(confidenceClass(50)).toBe("text-accent-open"); // Medium
      expect(confidenceClass(20)).toBe("text-accent-severe"); // Low
    });
  });
});
