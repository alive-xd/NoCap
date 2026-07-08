export interface AttackMapping {
  techniqueId: string;
  techniqueName: string;
  tactic: string;
  url: string;
}

export const MITRE_MAPPINGS: Record<string, AttackMapping> = {
  "T1566": {
    techniqueId: "T1566",
    techniqueName: "Phishing",
    tactic: "Initial Access",
    url: "https://attack.mitre.org/techniques/T1566/"
  },
  "T1583.003": {
    techniqueId: "T1583.003",
    techniqueName: "Acquire Infrastructure: Virtual Private Server",
    tactic: "Resource Development",
    url: "https://attack.mitre.org/techniques/T1583/003/"
  },
  "T1583.004": {
    techniqueId: "T1583.004",
    techniqueName: "Acquire Infrastructure: Server",
    tactic: "Resource Development",
    url: "https://attack.mitre.org/techniques/T1583/004/"
  },
  "T1583.001": {
    techniqueId: "T1583.001",
    techniqueName: "Acquire Infrastructure: Domains",
    tactic: "Resource Development",
    url: "https://attack.mitre.org/techniques/T1583/001/"
  },
  "T1592": {
    techniqueId: "T1592",
    techniqueName: "Gather Victim Host Information",
    tactic: "Reconnaissance",
    url: "https://attack.mitre.org/techniques/T1592/"
  },
  "T1588.006": {
    techniqueId: "T1588.006",
    techniqueName: "Obtain Capabilities: Vulnerabilities",
    tactic: "Resource Development",
    url: "https://attack.mitre.org/techniques/T1588/006/"
  },
  "T1568.002": {
    techniqueId: "T1568.002",
    techniqueName: "Dynamic Resolution: Domain Generation Algorithms",
    tactic: "Command and Control",
    url: "https://attack.mitre.org/techniques/T1568/002/"
  }
};

