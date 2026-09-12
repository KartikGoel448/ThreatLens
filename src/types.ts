export type RiskLevel = 'HIGH RISK' | 'SUSPICIOUS' | 'LOW RISK' | 'CLEAN';
export type VerdictType = 'POTENTIALLY MALICIOUS' | 'SUSPICIOUS' | 'CLEAN / LEGITIMATE';

export interface AuthProtocolResult {
  status: 'PASS' | 'FAIL' | 'NEUTRAL' | 'NONE';
  summary: string;
  details: string;
  record?: string;
  policy?: string;
  selector?: string;
}

export interface DomainIntelligence {
  domain: string;
  reputation: 'MALICIOUS' | 'SUSPICIOUS' | 'UNKNOWN' | 'TRUSTED';
  age: string;
  firstSeen: string;
  registrationCountry: string;
  summary: string;
  tags: string[];
  blocklistsCount?: number;

  // Real domain registration age intelligence
  domainAge: string;
  registrationDate: string | null;
  ageInDays: number | null;
  isRecentlyRegistered: boolean;
  lookupStatus: 'RECENTLY_REGISTERED' | 'ESTABLISHED' | 'UNAVAILABLE' | 'RATE_LIMITED' | 'ERROR';
  registrar?: string | null;
  provider?: string;
}

export interface FlaggedUrl {
  url: string;
  risk: 'HIGH RISK' | 'SUSPICIOUS' | 'CLEAN';
  reason: string;
  domain: string;
  category?: string;
}

export interface RelayHopGeolocation {
  status: 'SUCCESS' | 'PRIVATE_RESERVED' | 'UNAVAILABLE';
  country?: string | null;
  region?: string | null;
  city?: string | null;
  latitude?: number | null;
  longitude?: number | null;
  isp?: string | null;
  asn?: string | null;
  message?: string;
}

export interface RelayHop {
  hopNumber: number;
  name: string;
  role: 'SOURCE' | 'SUSPICIOUS' | 'WATCH' | 'TRUSTED' | 'DELIVERED';
  host: string;
  sendingHostname?: string;
  ip: string;
  ipType?: 'PUBLIC' | 'PRIVATE' | 'RESERVED' | 'DOCUMENTATION' | 'LOOPBACK' | 'UNAVAILABLE';
  location: string;
  timestamp: string;
  timezone?: string;
  delayFromPreviousHop?: string;
  delayMs?: number;
  response: string;
  reason: string;
  rawHeader?: string;
  geolocation?: RelayHopGeolocation;
  geo?: {
    x: number;
    y: number;
    label: string;
  };
}

export interface EvidenceItem {
  text: string;
  type: 'fail' | 'warn' | 'ok';
}

export interface GraphEntity {
  id: string;
  type: 'Email' | 'Domain' | 'IP Address' | 'URL' | 'Campaign Candidate';
  value: string;
  risk: 'HIGH' | 'SUSPICIOUS' | 'CLEAN';
  cls: 'fail' | 'warn' | 'pass' | 'info';
  firstSeen: string;
  count: number;
  related: string[];
  x?: number;
  y?: number;
  isCurrentCase?: boolean;
  caseId?: string;
  observedCases?: string[];
  relationship?: string;
  sharedEvidenceExplanation?: string;
  description?: string;
  meta?: Record<string, any>;
}

export interface GraphEdge {
  from: string;
  to: string;
  dashed?: boolean;
  hot?: boolean;
  label?: string;
}

export interface CaseCorrelationSharedEntity {
  type: string;
  value: string;
  relationship: string;
}

export interface RelatedCaseCorrelation {
  caseId: string;
  subject?: string;
  verdict?: VerdictType;
  riskScore?: number;
  timestamp?: string;
  sharedEntities: CaseCorrelationSharedEntity[];
}

export interface CampaignCandidateInfo {
  detected: boolean;
  confidence: number;
  reason: string;
  caseIds: string[];
  sharedEntities: Array<{
    type: string;
    value: string;
  }>;
}

export interface CaseCorrelationData {
  relatedCases: RelatedCaseCorrelation[];
  campaignCandidate: CampaignCandidateInfo;
  totalAnalyzedCasesCount: number;
}

export interface TechnicalDetails {
  rawHeaders: string;
  receivedChain: string[];
  observedIps: Array<{ ip: string; note: string }>;
  spfDetails: string;
  dkimDetails: string;
  dmarcDetails: string;
}

export interface AiContentFinding {
  category: string;
  severity: 'low' | 'medium' | 'high';
  confidence: number;
  evidence: string;
}

export interface AiContentAnalysis {
  contentAnalysisAvailable: boolean;
  findings: AiContentFinding[];
  overallAssessment: string;
}

export interface ForensicReportMetadata {
  generatedAt: string;
  canonicalHash: string;
  hashAlgorithm: 'SHA-256';
  disclaimer: string;
}

export interface CanonicalReportPayload {
  caseOverview: {
    caseId: string;
    timestamp: string;
    analyzedAt: string;
    verdict: string;
    riskScore: number;
    riskLevel: string;
    confidence: number | string;
  };
  senderDomainIntelligence: {
    fromAddress: string;
    displayName: string;
    returnPath: string;
    senderDomain: string;
    returnPathDomain: string;
    domainAlignmentStatus: string;
    registrationDate: string;
    domainAge: string;
    recentlyRegisteredStatus: string;
    registrar: string;
  };
  authenticationAnalysis: {
    spf: { status: string; details: string; summary: string };
    dkim: { status: string; details: string; summary: string };
    dmarc: { status: string; details: string; summary: string; policy: string };
    alignmentDiagnostics: string;
  };
  relayTrace: {
    hopsCount: number;
    hops: Array<{
      hopNumber: number;
      hostname: string;
      ip: string;
      ipClassification: string;
      timestamp: string;
      timezone: string;
      transitDelay: string;
      geolocation:
        | {
            status: string;
            country: string;
            region: string;
            city: string;
            isp: string;
            asn: string;
          }
        | string;
    }>;
    geolocationDisclaimer: string;
  };
  urlIntelligence: {
    count: number;
    urls: Array<{
      url: string;
      domain: string;
      classification: string;
      securityFinding: string;
    }>;
  };
  aiAssistedContentAnalysis: {
    available: boolean;
    model: string;
    overallAssessment: string;
    findingsCount: number;
    findings: Array<{
      category: string;
      severity: string;
      confidence: number;
      evidence: string;
    }>;
    label: string;
    probabilisticNotice: string;
  };
  investigationCorrelation: {
    relatedCaseIds: string[];
    sharedDomains: string[];
    sharedIps: string[];
    sharedUrls: string[];
    campaignCandidate: {
      detected: boolean;
      confidenceScore: number;
      reason: string;
    };
    attributionDisclaimer: string;
  };
  keyEvidence: Array<{
    source: string;
    type: string;
    evidence: string;
  }>;
}

export interface EmailAnalysisCase {
  caseId: string;
  timestamp: string;
  analyzedAt: string;
  verdict: VerdictType;
  riskScore: number;
  riskLevel: RiskLevel;
  confidence: number;
  sender: {
    displayName: string;
    email: string;
    domain: string;
    returnPath?: string;
  };
  recipient: {
    email: string;
  };
  subject: string;
  receivedDate: string;
  messageId: string;
  authResults: {
    spf: AuthProtocolResult;
    dkim: AuthProtocolResult;
    dmarc: AuthProtocolResult;
  };
  domainIntelligence: DomainIntelligence;
  domainAge: string;
  registrationDate: string | null;
  ageInDays: number | null;
  isRecentlyRegistered: boolean;
  lookupStatus: 'RECENTLY_REGISTERED' | 'ESTABLISHED' | 'UNAVAILABLE' | 'RATE_LIMITED' | 'ERROR';
  flaggedUrls: FlaggedUrl[];
  whyFlagged: {
    explanation: string;
    evidence: EvidenceItem[];
  };
  relayTrace: RelayHop[];
  graph: {
    entities: Record<string, GraphEntity>;
    edges: GraphEdge[];
    activeEntityKey?: string;
  };
  technicalDetails: TechnicalDetails;
  aiContentAnalysis?: AiContentAnalysis;
  correlation?: CaseCorrelationData;
  forensicReport?: ForensicReportMetadata;
}

export interface SampleEmailPreset {
  id: string;
  title: string;
  badge: string;
  badgeCls: 'fail' | 'warn' | 'pass';
  description: string;
  headers: string;
}
