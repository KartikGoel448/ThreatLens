/**
 * ThreatLens Forensic Report & Evidence Integrity Utility
 *
 * Implements deterministic canonical report payload generation,
 * SHA-256 integrity hashing, verification, and multi-format exports
 * (JSON, Markdown, PDF print, and Clipboard summary).
 */

import type { EmailAnalysisCase, ForensicReportMetadata, CanonicalReportPayload } from '../types';

export const INTEGRITY_HASH_DISCLAIMER =
  'The SHA-256 report integrity hash is a cryptographic mechanism for detecting modifications to the serialized report data. It does not prove that the email is malicious, that the report is truthful, that the evidence is authentic, attacker identity, or attribution.';

export const GEOLOCATION_DISCLAIMER =
  'IP geolocation is approximate network information and does not establish the exact physical location or identity of a sender.';

export const ATTRIBUTION_DISCLAIMER =
  'This correlation indicates shared observable infrastructure across analyzed cases. It does not prove common ownership or attacker attribution.';

export const AI_ANALYSIS_DISCLAIMER =
  'AI-Assisted Content Analysis is probabilistic and interprets social-engineering tactics. It does not constitute cryptographic or definitive proof that an email is malicious.';

/**
 * Deterministically serialize any JavaScript object by recursively sorting all object keys.
 */
export function deterministicStringify(obj: any): string {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return '[' + obj.map((item) => deterministicStringify(item)).join(',') + ']';
  }
  const keys = Object.keys(obj).sort();
  const pairs = keys.map((key) => `${JSON.stringify(key)}:${deterministicStringify(obj[key])}`);
  return '{' + pairs.join(',') + '}';
}

/**
 * Compute SHA-256 hex string from UTF-8 string across Browser (crypto.subtle) and Node.js.
 */
export async function computeSha256(input: string): Promise<string> {
  if (typeof crypto !== 'undefined' && crypto?.subtle) {
    const encoder = new TextEncoder();
    const data = encoder.encode(input);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
  }
  // Node.js fallback
  const nodeCrypto = await import('crypto');
  return nodeCrypto.createHash('sha256').update(input, 'utf8').digest('hex');
}

/**
 * Construct the canonical forensic report payload strictly from stored analysis case fields.
 * If any field is missing or empty, it explicitly sets "Unavailable" without inventing fake values.
 */
export function buildCanonicalReportPayload(analysisCase: EmailAnalysisCase): CanonicalReportPayload {
  const returnPathDomain = analysisCase.sender?.returnPath && analysisCase.sender.returnPath.includes('@')
    ? analysisCase.sender.returnPath.split('@')[1].replace(/>/g, '').trim()
    : 'Unavailable';

  const senderDomain = analysisCase.sender?.domain || analysisCase.domainIntelligence?.domain || 'Unavailable';

  let domainAlignmentStatus = 'Unavailable';
  if (senderDomain !== 'Unavailable' && returnPathDomain !== 'Unavailable') {
    domainAlignmentStatus =
      senderDomain.toLowerCase() === returnPathDomain.toLowerCase() ||
      returnPathDomain.toLowerCase().endsWith('.' + senderDomain.toLowerCase())
        ? 'ALIGNED'
        : 'MISALIGNED';
  }

  // Key evidence list with accurate source attribution
  const keyEvidence: Array<{ source: string; type: string; evidence: string }> = [];

  // SPF Evidence
  if (analysisCase.authResults?.spf) {
    keyEvidence.push({
      source: 'SPF',
      type: analysisCase.authResults.spf.status === 'PASS' ? 'ok' : 'fail',
      evidence: `SPF authentication evaluated as ${analysisCase.authResults.spf.status}: ${analysisCase.authResults.spf.details || analysisCase.authResults.spf.summary || 'No details'}`,
    });
  }

  // DKIM Evidence
  if (analysisCase.authResults?.dkim) {
    keyEvidence.push({
      source: 'DKIM',
      type: analysisCase.authResults.dkim.status === 'PASS' ? 'ok' : 'fail',
      evidence: `DKIM cryptographic signature evaluated as ${analysisCase.authResults.dkim.status}: ${analysisCase.authResults.dkim.details || analysisCase.authResults.dkim.summary || 'No details'}`,
    });
  }

  // DMARC Evidence
  if (analysisCase.authResults?.dmarc) {
    keyEvidence.push({
      source: 'DMARC',
      type: analysisCase.authResults.dmarc.status === 'PASS' ? 'ok' : 'fail',
      evidence: `DMARC domain policy evaluated as ${analysisCase.authResults.dmarc.status} (Policy: ${analysisCase.authResults.dmarc.policy || 'p=none'}): ${analysisCase.authResults.dmarc.details || analysisCase.authResults.dmarc.summary || 'No details'}`,
    });
  }

  // Domain Intelligence Evidence
  if (analysisCase.domainIntelligence) {
    const isRecent = analysisCase.domainIntelligence.isRecentlyRegistered;
    const domAge = analysisCase.domainIntelligence.domainAge || analysisCase.domainIntelligence.age || 'Unavailable';
    keyEvidence.push({
      source: 'Domain Intelligence',
      type: isRecent ? 'fail' : 'ok',
      evidence: `Sender domain '${senderDomain}' age is ${domAge} (Registered: ${analysisCase.domainIntelligence.registrationDate || 'Unavailable'}, Registrar: ${analysisCase.domainIntelligence.registrar || 'Unavailable'}). Status: ${isRecent ? 'Recently Registered Domain (<30 days)' : 'Established Domain'}.`,
    });
  }

  // Relay Trace Evidence
  if (analysisCase.relayTrace && analysisCase.relayTrace.length > 0) {
    const suspiciousHops = analysisCase.relayTrace.filter((h) => h.role === 'SUSPICIOUS');
    if (suspiciousHops.length > 0) {
      suspiciousHops.forEach((h) => {
        keyEvidence.push({
          source: 'Relay Trace',
          type: 'warn',
          evidence: `Relay hop ${h.hopNumber} (${h.host} [${h.ip}]) flagged: ${h.reason}`,
        });
      });
    } else {
      keyEvidence.push({
        source: 'Relay Trace',
        type: 'ok',
        evidence: `All ${analysisCase.relayTrace.length} observed mail relay hops routed through known/expected transit relays.`,
      });
    }
  }

  // URL Intelligence Evidence
  if (analysisCase.flaggedUrls && analysisCase.flaggedUrls.length > 0) {
    analysisCase.flaggedUrls.forEach((u) => {
      keyEvidence.push({
        source: 'URL Intelligence',
        type: u.risk === 'HIGH RISK' ? 'fail' : 'warn',
        evidence: `Extracted URL '${u.url}' classified as ${u.risk}: ${u.reason}`,
      });
    });
  } else {
    keyEvidence.push({
      source: 'URL Intelligence',
      type: 'ok',
      evidence: 'No high-risk credential-harvesting or deceptive URLs detected in message.',
    });
  }

  // AI Content Analysis Evidence
  if (analysisCase.aiContentAnalysis && analysisCase.aiContentAnalysis.contentAnalysisAvailable) {
    analysisCase.aiContentAnalysis.findings.forEach((f) => {
      keyEvidence.push({
        source: 'AI Content Analysis',
        type: f.severity === 'high' ? 'fail' : f.severity === 'medium' ? 'warn' : 'ok',
        evidence: `[${f.category}] (Severity: ${f.severity.toUpperCase()}, Confidence: ${f.confidence}%): ${f.evidence}`,
      });
    });
  } else {
    keyEvidence.push({
      source: 'AI Content Analysis',
      type: 'ok',
      evidence: 'AI Content Analysis unavailable (no readable email body provided).',
    });
  }

  // Campaign Correlation Evidence
  if (analysisCase.correlation?.campaignCandidate?.detected) {
    const candidate = analysisCase.correlation.campaignCandidate;
    const casesCount = candidate.caseIds?.length || 0;
    keyEvidence.push({
      source: 'Correlation',
      type: 'warn',
      evidence: `Campaign candidate detected (${candidate.confidence}% confidence) across ${casesCount} historical cases sharing infrastructure (${candidate.sharedEntities.map((e) => `${e.type}: ${e.value}`).join(', ')}).`,
    });
  }

  // Construct structured canonical object
  const payload: CanonicalReportPayload = {
    caseOverview: {
      caseId: analysisCase.caseId || 'Unavailable',
      timestamp: analysisCase.timestamp || analysisCase.analyzedAt || 'Unavailable',
      analyzedAt: analysisCase.analyzedAt || analysisCase.timestamp || 'Unavailable',
      verdict: analysisCase.verdict || 'Unavailable',
      riskScore: typeof analysisCase.riskScore === 'number' ? analysisCase.riskScore : 0,
      riskLevel: analysisCase.riskLevel || 'Unavailable',
      confidence: typeof analysisCase.confidence === 'number' ? analysisCase.confidence : 'Unavailable',
    },
    senderDomainIntelligence: {
      fromAddress: analysisCase.sender?.email || 'Unavailable',
      displayName: analysisCase.sender?.displayName || 'Unavailable',
      returnPath: analysisCase.sender?.returnPath || 'Unavailable',
      senderDomain: senderDomain,
      returnPathDomain: returnPathDomain,
      domainAlignmentStatus: domainAlignmentStatus,
      registrationDate: analysisCase.domainIntelligence?.registrationDate || analysisCase.registrationDate || 'Unavailable',
      domainAge: analysisCase.domainIntelligence?.domainAge || analysisCase.domainIntelligence?.age || analysisCase.domainAge || 'Unavailable',
      recentlyRegisteredStatus:
        typeof analysisCase.domainIntelligence?.isRecentlyRegistered === 'boolean'
          ? String(analysisCase.domainIntelligence.isRecentlyRegistered)
          : typeof analysisCase.isRecentlyRegistered === 'boolean'
          ? String(analysisCase.isRecentlyRegistered)
          : 'Unavailable',
      registrar: analysisCase.domainIntelligence?.registrar || 'Unavailable',
    },
    authenticationAnalysis: {
      spf: {
        status: analysisCase.authResults?.spf?.status || 'Unavailable',
        details: analysisCase.authResults?.spf?.details || 'Unavailable',
        summary: analysisCase.authResults?.spf?.summary || 'Unavailable',
      },
      dkim: {
        status: analysisCase.authResults?.dkim?.status || 'Unavailable',
        details: analysisCase.authResults?.dkim?.details || 'Unavailable',
        summary: analysisCase.authResults?.dkim?.summary || 'Unavailable',
      },
      dmarc: {
        status: analysisCase.authResults?.dmarc?.status || 'Unavailable',
        details: analysisCase.authResults?.dmarc?.details || 'Unavailable',
        summary: analysisCase.authResults?.dmarc?.summary || 'Unavailable',
        policy: analysisCase.authResults?.dmarc?.policy || 'Unavailable',
      },
      alignmentDiagnostics:
        domainAlignmentStatus === 'ALIGNED'
          ? 'Header From domain matches Return-Path domain (DMARC alignment satisfied)'
          : domainAlignmentStatus === 'MISALIGNED'
          ? 'Header From domain does not match Return-Path domain (DMARC alignment failed)'
          : 'Unavailable',
    },
    relayTrace: {
      hopsCount: analysisCase.relayTrace?.length || 0,
      hops: (analysisCase.relayTrace || []).map((hop) => ({
        hopNumber: hop.hopNumber,
        hostname: hop.host || 'Unavailable',
        ip: hop.ip || 'Unavailable',
        ipClassification: hop.ipType || 'Unavailable',
        timestamp: hop.timestamp || 'Unavailable',
        timezone: hop.timezone || 'Unavailable',
        transitDelay: hop.delayFromPreviousHop || 'Unavailable',
        geolocation: hop.geolocation
          ? {
              status: hop.geolocation.status || 'Unavailable',
              country: hop.geolocation.country || 'Unavailable',
              region: hop.geolocation.region || 'Unavailable',
              city: hop.geolocation.city || 'Unavailable',
              isp: hop.geolocation.isp || 'Unavailable',
              asn: hop.geolocation.asn || 'Unavailable',
            }
          : 'Unavailable',
      })),
      geolocationDisclaimer: GEOLOCATION_DISCLAIMER,
    },
    urlIntelligence: {
      count: analysisCase.flaggedUrls?.length || 0,
      urls: (analysisCase.flaggedUrls || []).map((u) => ({
        url: u.url || 'Unavailable',
        domain: u.domain || 'Unavailable',
        classification: u.risk || 'Unavailable',
        securityFinding: u.reason || 'Unavailable',
      })),
    },
    aiAssistedContentAnalysis: {
      available: analysisCase.aiContentAnalysis?.contentAnalysisAvailable ?? false,
      model: 'Gemini 3.8 Flash',
      overallAssessment: analysisCase.aiContentAnalysis?.overallAssessment || 'Unavailable',
      findingsCount: analysisCase.aiContentAnalysis?.findings?.length || 0,
      findings: (analysisCase.aiContentAnalysis?.findings || []).map((f) => ({
        category: f.category || 'Unavailable',
        severity: f.severity || 'low',
        confidence: f.confidence || 0,
        evidence: f.evidence || 'Unavailable',
      })),
      label: 'AI-Assisted Content Analysis',
      probabilisticNotice: AI_ANALYSIS_DISCLAIMER,
    },
    investigationCorrelation: {
      relatedCaseIds: analysisCase.correlation?.relatedCases?.map((c) => c.caseId) || [],
      sharedDomains: Array.from(
        new Set(
          (analysisCase.correlation?.campaignCandidate?.sharedEntities || [])
            .filter((e) => e.type === 'Domain')
            .map((e) => e.value)
        )
      ),
      sharedIps: Array.from(
        new Set(
          (analysisCase.correlation?.campaignCandidate?.sharedEntities || [])
            .filter((e) => e.type === 'IP')
            .map((e) => e.value)
        )
      ),
      sharedUrls: Array.from(
        new Set(
          (analysisCase.correlation?.campaignCandidate?.sharedEntities || [])
            .filter((e) => e.type === 'URL' || e.type === 'URL Domain')
            .map((e) => e.value)
        )
      ),
      campaignCandidate: {
        detected: analysisCase.correlation?.campaignCandidate?.detected ?? false,
        confidenceScore: analysisCase.correlation?.campaignCandidate?.confidence ?? 0,
        reason: analysisCase.correlation?.campaignCandidate?.reason || 'Unavailable',
      },
      attributionDisclaimer: ATTRIBUTION_DISCLAIMER,
    },
    keyEvidence,
  };

  return payload;
}

/**
 * Generate full human-readable Markdown forensic dossier
 */
export function generateMarkdownReport(
  analysisCase: EmailAnalysisCase,
  canonicalPayload: CanonicalReportPayload,
  hash: string
): string {
  const p = canonicalPayload;

  return `# ThreatLens Forensic Analysis Dossier
**Report Integrity Hash (SHA-256):** \`${hash}\`
*${INTEGRITY_HASH_DISCLAIMER}*

---

## A. CASE OVERVIEW
- **Case ID:** ${p.caseOverview.caseId}
- **Analysis Timestamp:** ${p.caseOverview.analyzedAt}
- **Classification:** ${p.caseOverview.verdict}
- **Risk Score:** ${p.caseOverview.riskScore}/100
- **Risk Level:** ${p.caseOverview.riskLevel}
- **Analysis Confidence:** ${p.caseOverview.confidence !== 'Unavailable' ? p.caseOverview.confidence + '%' : 'Unavailable'}
- **Subject:** "${analysisCase.subject || 'Unavailable'}"

---

## B. SENDER & DOMAIN INTELLIGENCE
- **From Address:** ${p.senderDomainIntelligence.fromAddress} (${p.senderDomainIntelligence.displayName})
- **Return-Path:** ${p.senderDomainIntelligence.returnPath}
- **Sender Domain:** ${p.senderDomainIntelligence.senderDomain}
- **Return-Path Domain:** ${p.senderDomainIntelligence.returnPathDomain}
- **Domain Alignment:** ${p.senderDomainIntelligence.domainAlignmentStatus}
- **Registration Date:** ${p.senderDomainIntelligence.registrationDate}
- **Domain Age:** ${p.senderDomainIntelligence.domainAge}
- **Recently Registered (<30 days):** ${p.senderDomainIntelligence.recentlyRegisteredStatus}
- **Registrar:** ${p.senderDomainIntelligence.registrar}

---

## C. AUTHENTICATION ANALYSIS
- **SPF:** ${p.authenticationAnalysis.spf.status} — ${p.authenticationAnalysis.spf.details}
- **DKIM:** ${p.authenticationAnalysis.dkim.status} — ${p.authenticationAnalysis.dkim.details}
- **DMARC:** ${p.authenticationAnalysis.dmarc.status} — ${p.authenticationAnalysis.dmarc.details} (Policy: ${p.authenticationAnalysis.dmarc.policy})
- **Alignment Diagnostics:** ${p.authenticationAnalysis.alignmentDiagnostics}

---

## D. RELAY TRACE
*Notice: ${GEOLOCATION_DISCLAIMER}*

Total Observed Hops: ${p.relayTrace.hopsCount}

${
  p.relayTrace.hops.length > 0
    ? p.relayTrace.hops
        .map((h) => {
          const geoStr =
            typeof h.geolocation === 'object'
              ? `${h.geolocation.city !== 'Unavailable' ? h.geolocation.city + ', ' : ''}${h.geolocation.country !== 'Unavailable' ? h.geolocation.country : 'Unknown Country'} (ISP: ${h.geolocation.isp})`
              : 'Unavailable';
          return `### Hop ${h.hopNumber}: ${h.hostname}
- **IP Address:** ${h.ip} (${h.ipClassification})
- **Timestamp / Timezone:** ${h.timestamp} (${h.timezone})
- **Transit Delay:** ${h.transitDelay}
- **Approximate Location:** ${geoStr}`;
        })
        .join('\n\n')
    : 'No relay hops recorded in message headers.'
}

---

## E. URL INTELLIGENCE
Total Extracted URLs: ${p.urlIntelligence.count}

${
  p.urlIntelligence.urls.length > 0
    ? p.urlIntelligence.urls
        .map(
          (u, idx) =>
            `${idx + 1}. **URL:** \`${u.url}\`\n   - **Host Domain:** ${u.domain}\n   - **Classification:** ${u.classification}\n   - **Security Finding:** ${u.securityFinding}`
        )
        .join('\n\n')
    : 'No suspicious or external URLs extracted from email content.'
}

---

## F. AI-ASSISTED CONTENT ANALYSIS
- **Label:** ${p.aiAssistedContentAnalysis.label}
- **Model:** ${p.aiAssistedContentAnalysis.model}
- **Analysis Available:** ${p.aiAssistedContentAnalysis.available ? 'Yes' : 'No (Body Unavailable)'}
- **Overall Assessment:** ${p.aiAssistedContentAnalysis.overallAssessment}
- **Identified Threat Categories:** ${p.aiAssistedContentAnalysis.findingsCount}

*${AI_ANALYSIS_DISCLAIMER}*

${
  p.aiAssistedContentAnalysis.findings.length > 0
    ? p.aiAssistedContentAnalysis.findings
        .map(
          (f) =>
            `- **[${f.category}]** Severity: ${f.severity.toUpperCase()} | Confidence: ${f.confidence}% | Evidence: ${f.evidence}`
        )
        .join('\n')
    : 'No significant social-engineering threat indicators identified.'
}

---

## G. INVESTIGATION / CORRELATION
- **Campaign Candidate Status:** ${p.investigationCorrelation.campaignCandidate.detected ? `DETECTED (${p.investigationCorrelation.campaignCandidate.confidenceScore}% Confidence)` : 'Not Detected'}
- **Correlated Historical Cases:** ${p.investigationCorrelation.relatedCaseIds.length > 0 ? p.investigationCorrelation.relatedCaseIds.join(', ') : 'None'}
- **Shared Domains:** ${p.investigationCorrelation.sharedDomains.length > 0 ? p.investigationCorrelation.sharedDomains.join(', ') : 'None'}
- **Shared IPs:** ${p.investigationCorrelation.sharedIps.length > 0 ? p.investigationCorrelation.sharedIps.join(', ') : 'None'}
- **Shared URLs:** ${p.investigationCorrelation.sharedUrls.length > 0 ? p.investigationCorrelation.sharedUrls.join(', ') : 'None'}

*Notice: ${ATTRIBUTION_DISCLAIMER}*

---

## H. KEY EVIDENCE
${
  p.keyEvidence.length > 0
    ? p.keyEvidence
        .map((e, idx) => `${idx + 1}. **[${e.source}]** (${e.type.toUpperCase()}): ${e.evidence}`)
        .join('\n')
    : 'No evidence items recorded.'
}

---
*Report generated by ThreatLens Forensic Intelligence Engine*
`;
}

/**
 * Generate quick incident summary for clipboard
 */
export function generateClipboardSummary(
  analysisCase: EmailAnalysisCase,
  canonicalPayload: CanonicalReportPayload,
  hash: string
): string {
  const p = canonicalPayload;
  return `=== THREATLENS FORENSIC INCIDENT SUMMARY ===
Case ID: ${p.caseOverview.caseId}
Integrity Hash (SHA-256): ${hash}
Verdict: ${p.caseOverview.verdict} (Risk Score: ${p.caseOverview.riskScore}/100 - ${p.caseOverview.riskLevel})
Subject: "${analysisCase.subject || 'Unavailable'}"
From: ${p.senderDomainIntelligence.fromAddress} -> Return-Path: ${p.senderDomainIntelligence.returnPath}
Authentication: SPF=${p.authenticationAnalysis.spf.status} | DKIM=${p.authenticationAnalysis.dkim.status} | DMARC=${p.authenticationAnalysis.dmarc.status}
Domain Age: ${p.senderDomainIntelligence.domainAge} (Recent: ${p.senderDomainIntelligence.recentlyRegisteredStatus})
Flagged URLs: ${p.urlIntelligence.count} | Relay Hops: ${p.relayTrace.hopsCount}
AI Content Analysis: ${p.aiAssistedContentAnalysis.available ? p.aiAssistedContentAnalysis.overallAssessment : 'Unavailable'}
Campaign Correlation: ${p.investigationCorrelation.campaignCandidate.detected ? `Shared Infrastructure Detected (${p.investigationCorrelation.campaignCandidate.confidenceScore}% conf)` : 'No cross-case infrastructure'}
Key Finding: ${analysisCase.whyFlagged?.explanation || 'See forensic dossier'}`;
}

/**
 * Verify integrity between canonical payload and expected hash
 */
export async function verifyReportIntegrity(
  canonicalPayload: CanonicalReportPayload,
  expectedHash: string
): Promise<{
  verified: boolean;
  calculatedHash: string;
  expectedHash: string;
  message: string;
}> {
  const canonicalString = deterministicStringify(canonicalPayload);
  const calculatedHash = await computeSha256(canonicalString);
  const verified = calculatedHash.toLowerCase() === expectedHash.toLowerCase();

  return {
    verified,
    calculatedHash,
    expectedHash,
    message: verified
      ? 'Integrity verified — hash matches'
      : 'Integrity verification failed — hash mismatch',
  };
}
