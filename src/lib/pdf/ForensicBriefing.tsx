import React from 'react';
import { Document, Page, Text, View, StyleSheet } from '@react-pdf/renderer';
import type { InvestigationDetail, Finding, Evidence } from '@/lib/pipeline/types';

const styles = StyleSheet.create({
  page: {
    padding: 40,
    fontFamily: 'Helvetica',
    backgroundColor: '#ffffff',
  },
  header: {
    marginBottom: 20,
    borderBottom: '1px solid #000000',
    paddingBottom: 10,
  },
  title: {
    fontSize: 24,
    fontWeight: 'bold',
    marginBottom: 4,
  },
  subtitle: {
    fontSize: 12,
    color: '#666666',
    marginBottom: 10,
  },
  metaRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginBottom: 4,
  },
  metaText: {
    fontSize: 10,
  },
  sectionTitle: {
    fontSize: 16,
    fontWeight: 'bold',
    marginTop: 20,
    marginBottom: 10,
    backgroundColor: '#f0f0f0',
    padding: 4,
  },
  findingCard: {
    marginBottom: 15,
    padding: 10,
    border: '1px solid #cccccc',
  },
  findingHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginBottom: 6,
  },
  findingClaim: {
    fontSize: 12,
    fontWeight: 'bold',
    width: '70%',
  },
  findingSeverity: {
    fontSize: 10,
    fontWeight: 'bold',
  },
  findingMeta: {
    fontSize: 10,
    color: '#666666',
    marginBottom: 6,
  },
  evidenceSection: {
    marginTop: 8,
    borderTop: '1px dashed #cccccc',
    paddingTop: 8,
  },
  evidenceTitle: {
    fontSize: 10,
    fontWeight: 'bold',
    marginBottom: 4,
  },
  evidenceItem: {
    flexDirection: 'row',
    marginBottom: 2,
  },
  evidenceKey: {
    fontSize: 9,
    width: '30%',
    color: '#666666',
  },
  evidenceValue: {
    fontSize: 9,
    width: '70%',
    fontFamily: 'Courier',
  },
});

interface Props {
  investigation: InvestigationDetail;
}

export function ForensicBriefing({ investigation }: Props) {
  return (
    <Document>
      <Page size="A4" style={styles.page}>
        <View style={styles.header}>
          <Text style={styles.title}>NoCap Forensic Briefing</Text>
          <Text style={styles.subtitle}>Confidential Security Report</Text>
          
          <View style={styles.metaRow}>
            <Text style={styles.metaText}>Case Number: {investigation.case_number}</Text>
            <Text style={styles.metaText}>Date: {new Date(investigation.created_at).toLocaleString()}</Text>
          </View>
          <View style={styles.metaRow}>
            <Text style={styles.metaText}>Target: {investigation.target}</Text>
            <Text style={styles.metaText}>Type: {investigation.target_type}</Text>
          </View>
          <View style={styles.metaRow}>
            <Text style={styles.metaText}>Final Verdict Score: {investigation.final_score ?? "N/A"}</Text>
            <Text style={styles.metaText}>Status: {investigation.status}</Text>
          </View>
        </View>

        <Text style={styles.sectionTitle}>Findings & Evidence</Text>

        {investigation.findings.map((f: Finding) => (
          <View key={f.id} style={styles.findingCard}>
            <View style={styles.findingHeader}>
              <Text style={styles.findingClaim}>{f.claim}</Text>
              <Text style={styles.findingSeverity}>{f.severity} (+{f.score_contribution})</Text>
            </View>
            <Text style={styles.findingMeta}>
              Analyzer: {f.generated_by} | MITRE: {f.attack_techniques?.join(', ') || 'N/A'}
            </Text>
            
            {f.evidence && f.evidence.length > 0 && (
              <View style={styles.evidenceSection}>
                <Text style={styles.evidenceTitle}>Extracted Evidence:</Text>
                {f.evidence.map((ev: Evidence, i: number) => (
                  <View key={i} style={styles.evidenceItem}>
                    <Text style={styles.evidenceKey}>{ev.fact_type}</Text>
                    <Text style={styles.evidenceValue}>
                      {typeof ev.fact_value === 'object' ? JSON.stringify(ev.fact_value) : String(ev.fact_value)}
                    </Text>
                  </View>
                ))}
              </View>
            )}
          </View>
        ))}
      </Page>
    </Document>
  );
}
