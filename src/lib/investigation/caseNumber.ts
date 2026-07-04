/**
 * Case Number Generator
 *
 * Generates case numbers in the format: NC-YYYY-NNNNN
 * Example: NC-2026-00142
 *
 * The sequence number is derived from the total count of investigations
 * for the given year, padded to 5 digits.
 */

export function generateCaseNumber(year: number, sequenceNumber: number): string {
  const paddedSeq = String(sequenceNumber).padStart(5, "0");
  return `NC-${year}-${paddedSeq}`;
}

export function parseCaseNumber(caseNumber: string): {
  prefix: string;
  year: number;
  sequence: number;
} | null {
  const match = caseNumber.match(/^NC-(\d{4})-(\d{5})$/);
  if (!match) return null;
  return {
    prefix: "NC",
    year: parseInt(match[1], 10),
    sequence: parseInt(match[2], 10),
  };
}
