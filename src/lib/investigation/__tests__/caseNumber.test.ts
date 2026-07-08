import { describe, it, expect } from "vitest";
import { generateCaseNumber, parseCaseNumber } from "../caseNumber";

describe("caseNumber", () => {
  describe("generateCaseNumber", () => {
    it("generates a case number with zero padding to 5 digits", () => {
      expect(generateCaseNumber(2026, 142)).toBe("NC-2026-00142");
      expect(generateCaseNumber(2024, 1)).toBe("NC-2024-00001");
      expect(generateCaseNumber(2025, 99999)).toBe("NC-2025-99999");
    });

    it("does not truncate if sequence exceeds 5 digits", () => {
      expect(generateCaseNumber(2026, 123456)).toBe("NC-2026-123456");
    });
  });

  describe("parseCaseNumber", () => {
    it("parses a valid case number", () => {
      expect(parseCaseNumber("NC-2026-00142")).toEqual({
        prefix: "NC",
        year: 2026,
        sequence: 142,
      });
      
      expect(parseCaseNumber("NC-2024-00001")).toEqual({
        prefix: "NC",
        year: 2024,
        sequence: 1,
      });
    });

    it("returns null for invalid formats", () => {
      expect(parseCaseNumber("NOCAP-2026-00142")).toBeNull();
      expect(parseCaseNumber("NC-26-00142")).toBeNull(); // Year not 4 digits
      expect(parseCaseNumber("NC-2026-142")).toBeNull(); // Sequence not 5 digits
      expect(parseCaseNumber("")).toBeNull();
      expect(parseCaseNumber("random string")).toBeNull();
    });
  });
});
