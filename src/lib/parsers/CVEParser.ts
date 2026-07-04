import type { Parser, ParsedEvidence } from "@/lib/pipeline/types";

export class CVEParser implements Parser {
  readonly name = "CVEParser";
  readonly version = "1.0";

  parse(raw: Record<string, unknown>): ParsedEvidence[] {
    const cve = (raw.cve as Record<string, unknown>) ?? {};
    const cveId = (cve.id as string) ?? "";

    // Extract CVSS score
    let cvssScore = 0;
    const metrics = (cve.metrics as Record<string, unknown>) ?? {};
    
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const cvssMetricV31 = (metrics.cvssMetricV31 as any[]) ?? [];
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const cvssMetricV30 = (metrics.cvssMetricV30 as any[]) ?? [];
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const cvssMetricV2 = (metrics.cvssMetricV2 as any[]) ?? [];

    if (cvssMetricV31.length > 0 && cvssMetricV31[0]?.cvssData?.baseScore !== undefined) {
      cvssScore = cvssMetricV31[0].cvssData.baseScore;
    } else if (cvssMetricV30.length > 0 && cvssMetricV30[0]?.cvssData?.baseScore !== undefined) {
      cvssScore = cvssMetricV30[0].cvssData.baseScore;
    } else if (cvssMetricV2.length > 0 && cvssMetricV2[0]?.cvssData?.baseScore !== undefined) {
      cvssScore = cvssMetricV2[0].cvssData.baseScore;
    }

    const descriptions = (cve.descriptions as Array<{ lang: string; value: string }>) ?? [];
    const descObj = descriptions.find((d) => d.lang === "en") ?? descriptions[0];
    const description = descObj?.value ?? "";

    const publishDate = (cve.published as string) ?? new Date().toISOString();
    const hasKnownExploit = (raw.has_known_exploit as boolean) ?? false;
    const inCisaKev = (raw.in_cisa_kev as boolean) ?? false;

    return [
      { fact_type: "cve_id", fact_value: cveId },
      { fact_type: "cvss_score", fact_value: cvssScore },
      { fact_type: "publish_date", fact_value: publishDate },
      { fact_type: "has_known_exploit", fact_value: hasKnownExploit },
      { fact_type: "in_cisa_kev", fact_value: inCisaKev },
      { fact_type: "description", fact_value: description },
    ];
  }
}
