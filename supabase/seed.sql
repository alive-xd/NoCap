-- NoCap: Seed Data
-- Scoring Profile v1.0 — frozen weights with reasoning

INSERT INTO scoring_profiles (version, source_weights, reasoning)
VALUES (
  '1.0',
  '{
    "virustotal": 40,
    "abuseipdb": 20,
    "entropy": 15,
    "domain_age": 15,
    "asn_reputation": 10
  }',
  '{
    "virustotal": "Multi-vendor consensus is the strongest single signal for malicious classification. 40 points reflects that agreement across 70+ independent AV engines is highly reliable.",
    "abuseipdb": "Community-reported abuse is a strong corroborating signal. 20 points reflects crowd-sourced intelligence with some false-positive risk.",
    "entropy": "High Shannon entropy strongly correlates with DGA (domain generation algorithm) usage in malware C2 infrastructure. 15 points reflects this as a structural signal, not behavioral.",
    "domain_age": "Newly registered domains are disproportionately used in phishing and malware campaigns before blocklists catch them. 15 points reflects recency as a meaningful risk factor.",
    "asn_reputation": "ASN-level reputation is a useful network-tier signal but is coarse — large ASNs host both malicious and legitimate traffic. 10 points reflects its value as a corroborating factor only."
  }'
)
ON CONFLICT (version) DO NOTHING;
