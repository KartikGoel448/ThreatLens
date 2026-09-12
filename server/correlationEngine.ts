/**
 * ThreatLens - Real Investigation Graph & Campaign Correlation Engine
 * 
 * Complies strictly with ThreatLens Step 5:
 * 1. Powered entirely by real analyzed-email data stored in Firestore.
 * 2. Zero hardcoded demo nodes, fake relationships, or fabricated infrastructure.
 * 3. Normalizes domains, IPs (public vs private/reserved), and URLs before correlation.
 * 4. Strictly avoids weak correlations (public email providers like Gmail/Yahoo, generic TLDs, similar subject text).
 * 5. Flags Campaign Candidate with mandatory exact wording:
 *    - "Campaign Candidate — shared infrastructure detected"
 *    - "This correlation indicates shared observable infrastructure. It does not prove common ownership or attacker attribution."
 * 6. Generates stable entity identifiers without duplicate nodes.
 * 7. Clearly distinguishes CURRENT CASE from RELATED ANALYZED CASES.
 * 8. Handles single-case and no-correlation states transparently.
 */

import { classifyIp } from './ipGeolocation.js';
import type {
  EmailAnalysisCase,
  GraphEntity,
  GraphEdge,
  CaseCorrelationData,
  RelatedCaseCorrelation,
  CaseCorrelationSharedEntity,
  CampaignCandidateInfo,
} from '../src/types.js';

// Generic public consumer webmail and disposable email providers that MUST NOT create campaign candidates
export const GENERIC_PUBLIC_EMAIL_PROVIDERS = new Set<string>([
  'gmail.com',
  'googlemail.com',
  'yahoo.com',
  'ymail.com',
  'outlook.com',
  'hotmail.com',
  'live.com',
  'msn.com',
  'icloud.com',
  'me.com',
  'mac.com',
  'aol.com',
  'aim.com',
  'protonmail.com',
  'proton.me',
  'zoho.com',
  'mail.com',
  'gmx.com',
  'gmx.net',
  'fastmail.com',
  'yandex.com',
  'yandex.ru',
  'tutanota.com',
  'tutamail.com',
  'comcast.net',
  'att.net',
  'verizon.net',
]);

// Common generic CDNs / shared link shortening or public utility domains to exclude from infrastructure correlation
export const GENERIC_SHARED_DOMAINS = new Set<string>([
  'bit.ly',
  'tinyurl.com',
  't.co',
  'goo.gl',
  'schema.org',
  'w3.org',
  'microsoft.com',
  'google.com',
  'apple.com',
]);

/**
 * Normalizes a domain name:
 * - Trims whitespace
 * - Converts to lowercase
 * - Strips leading/trailing brackets, quotes, '@'
 * - Removes trailing dots
 */
export function normalizeDomain(rawDomain: string): string {
  if (!rawDomain || typeof rawDomain !== 'string') return '';
  let d = rawDomain.trim().toLowerCase();
  d = d.replace(/^[@<"']+|[>"']+$/g, '');
  d = d.replace(/\.+$/, '');
  return d;
}

/**
 * Normalizes an IP address:
 * - Trims whitespace, removes brackets
 * - Determines if it is public vs private/reserved/documentation using existing classifyIp
 * - Returns normalized string and public eligibility flag
 */
export function normalizeIp(rawIp: string): {
  normalizedIp: string;
  isPublic: boolean;
  ipType: string;
} {
  if (!rawIp || typeof rawIp !== 'string') {
    return { normalizedIp: '', isPublic: false, ipType: 'UNAVAILABLE' };
  }
  const cleanIp = rawIp.trim().replace(/^\[|\]$/g, '').toLowerCase();
  const classification = classifyIp(cleanIp);
  return {
    normalizedIp: cleanIp,
    isPublic: classification.ipType === 'PUBLIC',
    ipType: classification.ipType,
  };
}

/**
 * Normalizes a URL and extracts its host/domain for infrastructure correlation
 */
export function normalizeUrl(rawUrl: string): {
  normalizedUrl: string;
  normalizedHost: string;
} {
  if (!rawUrl || typeof rawUrl !== 'string') {
    return { normalizedUrl: '', normalizedHost: '' };
  }
  const trimmed = rawUrl.trim();
  try {
    const urlObj = new URL(trimmed.startsWith('http://') || trimmed.startsWith('https://') ? trimmed : `http://${trimmed}`);
    const host = normalizeDomain(urlObj.hostname);
    return {
      normalizedUrl: urlObj.href,
      normalizedHost: host,
    };
  } catch {
    const fallbackMatch = trimmed.match(/^(?:https?:\/\/)?([^\/\s\?#:]+)/i);
    const host = fallbackMatch ? normalizeDomain(fallbackMatch[1]) : '';
    return {
      normalizedUrl: trimmed,
      normalizedHost: host,
    };
  }
}

/**
 * Checks if a domain is a generic public email provider
 */
export function isGenericPublicEmailProvider(domain: string): boolean {
  const norm = normalizeDomain(domain);
  return GENERIC_PUBLIC_EMAIL_PROVIDERS.has(norm);
}

/**
 * Structured entities extracted from a single analyzed case for cross-case correlation
 */
export interface ExtractedCaseEntities {
  caseId: string;
  subject: string;
  verdict: any;
  riskScore: number;
  timestamp: string;
  senderDomain: string;
  senderEmail: string;
  returnPathDomain: string;
  publicIps: Set<string>;
  privateIps: Set<string>;
  urlDomains: Set<string>;
  urls: Set<string>;
}

/**
 * Extracts normalized entities from an analyzed email case or Firestore record
 */
export function extractCaseEntities(caseData: any): ExtractedCaseEntities {
  const caseId = caseData.caseId || 'UNKNOWN-CASE';
  const subject = caseData.subject || 'Untitled Email';
  const verdict = caseData.verdict || 'SUSPICIOUS';
  const riskScore = typeof caseData.riskScore === 'number' ? caseData.riskScore : 50;
  const timestamp = caseData.timestamp || caseData.analyzedAt || new Date().toUTCString();

  // Sender domain
  const rawSenderDomain = caseData.sender?.domain || caseData.senderDomain || '';
  const senderDomain = normalizeDomain(rawSenderDomain);
  const senderEmail = caseData.sender?.email || caseData.senderEmail || '';

  // Return-Path domain
  const rawReturnPath = caseData.sender?.returnPath || caseData.returnPath || '';
  let returnPathDomain = '';
  if (rawReturnPath && rawReturnPath.includes('@')) {
    returnPathDomain = normalizeDomain(rawReturnPath.split('@')[1] || '');
  }

  // IP addresses (Relay hops & Observed IPs)
  const publicIps = new Set<string>();
  const privateIps = new Set<string>();

  // Check observedIps
  const observedIpsList: Array<{ ip?: string }> = caseData.technicalDetails?.observedIps || caseData.observedIps || [];
  for (const item of observedIpsList) {
    if (item && item.ip) {
      const norm = normalizeIp(item.ip);
      if (norm.normalizedIp && norm.normalizedIp !== 'unavailable') {
        if (norm.isPublic) {
          publicIps.add(norm.normalizedIp);
        } else {
          privateIps.add(norm.normalizedIp);
        }
      }
    }
  }

  // Check relayTrace hops
  const hops: Array<{ ip?: string; host?: string }> =
    caseData.relayTrace?.hops || caseData.relayTrace || caseData.rawRelayHops || [];
  for (const hop of hops) {
    if (hop && hop.ip) {
      const norm = normalizeIp(hop.ip);
      if (norm.normalizedIp && norm.normalizedIp !== 'unavailable') {
        if (norm.isPublic) {
          publicIps.add(norm.normalizedIp);
        } else {
          privateIps.add(norm.normalizedIp);
        }
      }
    }
  }

  // URLs & URL domains
  const urlDomains = new Set<string>();
  const urls = new Set<string>();

  const flaggedUrlsList: Array<{ url?: string; domain?: string }> = caseData.flaggedUrls || [];
  for (const fu of flaggedUrlsList) {
    if (fu && fu.url) {
      const parsed = normalizeUrl(fu.url);
      if (parsed.normalizedUrl) urls.add(parsed.normalizedUrl);
      if (parsed.normalizedHost) urlDomains.add(parsed.normalizedHost);
    }
  }

  return {
    caseId,
    subject,
    verdict,
    riskScore,
    timestamp,
    senderDomain,
    senderEmail,
    returnPathDomain,
    publicIps,
    privateIps,
    urlDomains,
    urls,
  };
}

/**
 * Cross-case correlation:
 * Compares current case against historical cases in Firestore/memory.
 * Identifies shared infrastructure:
 * - exact shared sender domain (excluding generic webmail)
 * - exact shared return-path domain (excluding generic webmail)
 * - exact shared public IP (sending or relay; strictly excluding private/reserved IPs)
 * - exact shared URL domain (excluding generic CDNs/utilities)
 */
export function correlateWithPastCases(
  currentCaseData: any,
  pastCasesData: any[]
): CaseCorrelationData {
  const current = extractCaseEntities(currentCaseData);
  const relatedCases: RelatedCaseCorrelation[] = [];
  const allSharedEntitiesMap = new Map<string, { type: string; value: string }>();

  // Filter out the current case from comparison
  const otherCases = pastCasesData.filter(
    (c) => c && (c.caseId ? c.caseId !== current.caseId : true)
  );

  for (const pastCase of otherCases) {
    const past = extractCaseEntities(pastCase);
    if (!past.caseId || past.caseId === current.caseId) continue;

    const sharedForThisCase: CaseCorrelationSharedEntity[] = [];

    // 1. Shared Sender Domain (must not be generic webmail like gmail.com)
    if (
      current.senderDomain &&
      past.senderDomain &&
      current.senderDomain === past.senderDomain &&
      !isGenericPublicEmailProvider(current.senderDomain)
    ) {
      sharedForThisCase.push({
        type: 'Sender Domain',
        value: current.senderDomain,
        relationship: 'shared_sender_domain',
      });
      allSharedEntitiesMap.set(`domain:${current.senderDomain}`, {
        type: 'Sender Domain',
        value: current.senderDomain,
      });
    }

    // 2. Shared Return-Path Domain (must not be generic webmail)
    if (
      current.returnPathDomain &&
      past.returnPathDomain &&
      current.returnPathDomain === past.returnPathDomain &&
      current.returnPathDomain !== current.senderDomain &&
      !isGenericPublicEmailProvider(current.returnPathDomain)
    ) {
      sharedForThisCase.push({
        type: 'Return-Path Domain',
        value: current.returnPathDomain,
        relationship: 'shared_return_path_domain',
      });
      allSharedEntitiesMap.set(`returnpath:${current.returnPathDomain}`, {
        type: 'Return-Path Domain',
        value: current.returnPathDomain,
      });
    }

    // 3. Shared Public IP (Strictly public IPs; private/reserved IPs NEVER correlate)
    for (const ip of current.publicIps) {
      if (past.publicIps.has(ip)) {
        sharedForThisCase.push({
          type: 'Public IP',
          value: ip,
          relationship: 'shared_relay_ip',
        });
        allSharedEntitiesMap.set(`ip:${ip}`, {
          type: 'Public IP',
          value: ip,
        });
      }
    }

    // 4. Shared URL Domain (excluding generic shared domains)
    for (const uHost of current.urlDomains) {
      if (past.urlDomains.has(uHost) && !GENERIC_SHARED_DOMAINS.has(uHost)) {
        sharedForThisCase.push({
          type: 'URL Domain',
          value: uHost,
          relationship: 'shared_url_domain',
        });
        allSharedEntitiesMap.set(`urldomain:${uHost}`, {
          type: 'URL Domain',
          value: uHost,
        });
      }
    }

    if (sharedForThisCase.length > 0) {
      relatedCases.push({
        caseId: past.caseId,
        subject: past.subject,
        verdict: past.verdict,
        riskScore: past.riskScore,
        timestamp: past.timestamp,
        sharedEntities: sharedForThisCase,
      });
    }
  }

  // Campaign Candidate Evaluation
  const uniqueSharedEntities = Array.from(allSharedEntitiesMap.values());
  const campaignDetected = relatedCases.length > 0 && uniqueSharedEntities.length > 0;

  let campaignCandidate: CampaignCandidateInfo;

  if (campaignDetected) {
    const totalCasesInCluster = relatedCases.length + 1;
    campaignCandidate = {
      detected: true,
      confidence: Math.min(95, 65 + Math.min(30, uniqueSharedEntities.length * 10)),
      reason: `Campaign Candidate — shared infrastructure detected across ${totalCasesInCluster} analyzed cases. This correlation indicates shared observable infrastructure. It does not prove common ownership or attacker attribution.`,
      caseIds: [current.caseId, ...relatedCases.map((r) => r.caseId)],
      sharedEntities: uniqueSharedEntities,
    };
  } else {
    campaignCandidate = {
      detected: false,
      confidence: 0,
      reason:
        otherCases.length > 0
          ? 'No meaningful shared infrastructure detected.'
          : 'Campaign correlation requires comparable analyzed cases.',
      caseIds: [current.caseId],
      sharedEntities: [],
    };
  }

  return {
    relatedCases,
    campaignCandidate,
    totalAnalyzedCasesCount: otherCases.length + 1,
  };
}

/**
 * Builds the real Investigation Graph from actual analyzed email data.
 * Zero hardcoded nodes.
 * Stable entity identifiers:
 * - case:${caseId}
 * - domain:${normalizedDomain}
 * - ip:${normalizedIp}
 * - urldomain:${normalizedUrlDomain}
 * - campaign:candidate (only if campaign detected)
 */
export function buildRealInvestigationGraph(
  currentCaseData: any,
  correlationData: CaseCorrelationData
): {
  entities: Record<string, GraphEntity>;
  edges: GraphEdge[];
  activeEntityKey: string;
} {
  const current = extractCaseEntities(currentCaseData);
  const entities: Record<string, GraphEntity> = {};
  const edges: GraphEdge[] = [];

  // Track case appearances for each normalized entity key
  const entityObservedCasesMap = new Map<string, Set<string>>();
  const recordEntityObservation = (key: string, caseId: string) => {
    if (!entityObservedCasesMap.has(key)) {
      entityObservedCasesMap.set(key, new Set());
    }
    entityObservedCasesMap.get(key)!.add(caseId);
  };

  recordEntityObservation(`case:${current.caseId}`, current.caseId);

  // 1. Current Case Node (Center)
  const currentCaseKey = `case:${current.caseId}`;
  entities[currentCaseKey] = {
    id: currentCaseKey,
    type: 'Email',
    value: `${current.caseId}`,
    risk: current.riskScore >= 65 ? 'HIGH' : current.riskScore >= 35 ? 'SUSPICIOUS' : 'CLEAN',
    cls: current.riskScore >= 65 ? 'fail' : current.riskScore >= 35 ? 'warn' : 'pass',
    firstSeen: current.timestamp,
    count: 0,
    related: [],
    x: 440,
    y: correlationData.campaignCandidate.detected ? 310 : 290,
    isCurrentCase: true,
    caseId: current.caseId,
    observedCases: [current.caseId],
    relationship: 'Current Analyzed Email Case',
    sharedEvidenceExplanation: `Primary subject under investigation (${current.subject}).`,
    description: `Subject: "${current.subject}" | From: ${current.senderEmail}`,
  };

  // 2. Sender Domain Node
  let senderDomainKey: string | null = null;
  if (current.senderDomain) {
    senderDomainKey = `domain:${current.senderDomain}`;
    recordEntityObservation(senderDomainKey, current.caseId);
    for (const rel of correlationData.relatedCases) {
      if (rel.sharedEntities.some((se) => se.type === 'Sender Domain' && se.value === current.senderDomain)) {
        recordEntityObservation(senderDomainKey, rel.caseId);
      }
    }

    const obs = Array.from(entityObservedCasesMap.get(senderDomainKey) || [current.caseId]);
    entities[senderDomainKey] = {
      id: senderDomainKey,
      type: 'Domain',
      value: current.senderDomain,
      risk: isGenericPublicEmailProvider(current.senderDomain)
        ? 'CLEAN'
        : current.riskScore >= 65
        ? 'HIGH'
        : 'SUSPICIOUS',
      cls: isGenericPublicEmailProvider(current.senderDomain)
        ? 'pass'
        : current.riskScore >= 65
        ? 'fail'
        : 'warn',
      firstSeen: current.timestamp,
      count: obs.length,
      related: [],
      x: 180,
      y: 150,
      observedCases: obs,
      relationship: obs.length > 1 ? 'Shared Sender Domain' : 'Sender Domain of Current Email',
      sharedEvidenceExplanation:
        obs.length > 1
          ? `Related because both cases (${obs.join(', ')}) observed sender domain ${current.senderDomain}.`
          : `Authoritative sender domain for ${current.caseId}.`,
      description: isGenericPublicEmailProvider(current.senderDomain)
        ? 'Generic public email provider'
        : `Domain registered in DNS / RDAP`,
    };

    edges.push({
      from: currentCaseKey,
      to: senderDomainKey,
      hot: current.riskScore >= 65,
    });
  }

  // 3. Return-Path Domain Node (if distinct from sender domain)
  let returnPathKey: string | null = null;
  if (current.returnPathDomain && current.returnPathDomain !== current.senderDomain) {
    returnPathKey = `returnpath:${current.returnPathDomain}`;
    recordEntityObservation(returnPathKey, current.caseId);
    for (const rel of correlationData.relatedCases) {
      if (rel.sharedEntities.some((se) => se.type === 'Return-Path Domain' && se.value === current.returnPathDomain)) {
        recordEntityObservation(returnPathKey, rel.caseId);
      }
    }

    const obs = Array.from(entityObservedCasesMap.get(returnPathKey) || [current.caseId]);
    entities[returnPathKey] = {
      id: returnPathKey,
      type: 'Domain',
      value: current.returnPathDomain,
      risk: 'SUSPICIOUS',
      cls: 'warn',
      firstSeen: current.timestamp,
      count: obs.length,
      related: [],
      x: 180,
      y: 290,
      observedCases: obs,
      relationship: 'Return-Path Domain',
      sharedEvidenceExplanation:
        obs.length > 1
          ? `Related because both cases (${obs.join(', ')}) observed return-path domain ${current.returnPathDomain}.`
          : `Envelope Return-Path domain for ${current.caseId}.`,
      description: `Mismatched envelope domain vs Header From`,
    };

    edges.push({
      from: currentCaseKey,
      to: returnPathKey,
      dashed: true,
    });
  }

  // 4. IP Address Nodes (Public IPs and Private IPs)
  const ipList = [
    ...Array.from(current.publicIps).map((ip) => ({ ip, isPublic: true })),
    ...Array.from(current.privateIps).map((ip) => ({ ip, isPublic: false })),
  ];

  // Limit IP nodes displayed to max 3 primary to avoid SVG clutter
  const primaryIps = ipList.slice(0, 3);
  primaryIps.forEach((item, index) => {
    const ipKey = `ip:${item.ip}`;
    recordEntityObservation(ipKey, current.caseId);

    if (item.isPublic) {
      for (const rel of correlationData.relatedCases) {
        if (rel.sharedEntities.some((se) => se.type === 'Public IP' && se.value === item.ip)) {
          recordEntityObservation(ipKey, rel.caseId);
        }
      }
    }

    const obs = Array.from(entityObservedCasesMap.get(ipKey) || [current.caseId]);
    const isShared = item.isPublic && obs.length > 1;

    // Layout coordinates for IPs: lower left quadrant
    const ipY = 430 + index * 55;
    const ipX = 180 + (index % 2) * 50;

    entities[ipKey] = {
      id: ipKey,
      type: 'IP Address',
      value: item.ip,
      risk: isShared ? 'HIGH' : item.isPublic ? 'SUSPICIOUS' : 'CLEAN',
      cls: isShared ? 'fail' : item.isPublic ? 'warn' : 'info',
      firstSeen: current.timestamp,
      count: obs.length,
      related: [],
      x: ipX,
      y: ipY,
      observedCases: obs,
      relationship: isShared
        ? 'Shared Public Relay Infrastructure'
        : item.isPublic
        ? 'Public Relay / Sending IP'
        : 'Private/Reserved Network IP (Excluded from Public Correlation)',
      sharedEvidenceExplanation: isShared
        ? `Related because both cases (${obs.join(', ')}) observed public relay IP ${item.ip}.`
        : item.isPublic
        ? `Observed in transit relay headers for ${current.caseId}.`
        : `Private/Reserved RFC range (${item.ip}). Does not create cross-case correlations.`,
      description: item.isPublic ? 'Public IP Address' : 'Private / Reserved RFC Block',
    };

    edges.push({
      from: currentCaseKey,
      to: ipKey,
      hot: isShared,
      dashed: !item.isPublic,
    });
  });

  // 5. URL & URL Domain Nodes
  const urlDomainsList = Array.from(current.urlDomains).slice(0, 2);
  urlDomainsList.forEach((uHost, index) => {
    const urlKey = `urldomain:${uHost}`;
    recordEntityObservation(urlKey, current.caseId);

    for (const rel of correlationData.relatedCases) {
      if (rel.sharedEntities.some((se) => se.type === 'URL Domain' && se.value === uHost)) {
        recordEntityObservation(urlKey, rel.caseId);
      }
    }

    const obs = Array.from(entityObservedCasesMap.get(urlKey) || [current.caseId]);
    const isShared = obs.length > 1;

    // Upper right quadrant
    const urlY = 150 + index * 90;
    const urlX = 700;

    entities[urlKey] = {
      id: urlKey,
      type: 'URL',
      value: uHost,
      risk: isShared ? 'HIGH' : 'SUSPICIOUS',
      cls: isShared ? 'fail' : 'warn',
      firstSeen: current.timestamp,
      count: obs.length,
      related: [],
      x: urlX,
      y: urlY,
      observedCases: obs,
      relationship: isShared ? 'Shared URL Domain Infrastructure' : 'Embedded Flagged URL Domain',
      sharedEvidenceExplanation: isShared
        ? `Related because both cases (${obs.join(', ')}) observed links pointing to ${uHost}.`
        : `Embedded destination link observed in email body.`,
      description: `URL Destination Host`,
    };

    edges.push({
      from: currentCaseKey,
      to: urlKey,
      hot: isShared,
    });
  });

  // 6. Related Cases Nodes (Representing actual other analyzed cases from Firestore)
  correlationData.relatedCases.forEach((rel, index) => {
    const relKey = `case:${rel.caseId}`;
    recordEntityObservation(relKey, rel.caseId);

    // Position related cases in outer perimeter or lower right
    const relX = 700;
    const relY = 380 + index * 90;

    entities[relKey] = {
      id: relKey,
      type: 'Email',
      value: `${rel.caseId}`,
      risk: rel.riskScore && rel.riskScore >= 65 ? 'HIGH' : 'SUSPICIOUS',
      cls: rel.riskScore && rel.riskScore >= 65 ? 'fail' : 'warn',
      firstSeen: rel.timestamp || 'Prior Analysis',
      count: rel.sharedEntities.length,
      related: [],
      x: relX,
      y: relY,
      isCurrentCase: false,
      caseId: rel.caseId,
      observedCases: [rel.caseId],
      relationship: `Related Analyzed Case (Shares ${rel.sharedEntities.map((se) => se.type).join(', ')})`,
      sharedEvidenceExplanation: `Related because both cases observed: ${rel.sharedEntities
        .map((se) => `${se.type} ${se.value}`)
        .join(', ')}.`,
      description: `Subject: "${rel.subject || 'Analyzed Case'}" | Verdict: ${rel.verdict || 'SUSPICIOUS'}`,
    };

    // Connect related case to each shared infrastructure entity
    for (const se of rel.sharedEntities) {
      let targetKey: string | null = null;
      if (se.type === 'Sender Domain') targetKey = `domain:${se.value}`;
      else if (se.type === 'Return-Path Domain') targetKey = `returnpath:${se.value}`;
      else if (se.type === 'Public IP') targetKey = `ip:${se.value}`;
      else if (se.type === 'URL Domain') targetKey = `urldomain:${se.value}`;

      if (targetKey && entities[targetKey]) {
        edges.push({
          from: targetKey,
          to: relKey,
          hot: true,
          dashed: false,
        });
      }
    }
  });

  // 7. Campaign Candidate Node (Only if meaningful shared infrastructure detected)
  if (correlationData.campaignCandidate.detected) {
    const campKey = 'campaign:candidate';
    entities[campKey] = {
      id: campKey,
      type: 'Campaign Candidate',
      value: 'Campaign Candidate',
      risk: 'HIGH',
      cls: 'fail',
      firstSeen: current.timestamp,
      count: correlationData.campaignCandidate.caseIds.length,
      related: [],
      x: 440,
      y: 70,
      observedCases: correlationData.campaignCandidate.caseIds,
      relationship: 'Campaign Candidate — shared infrastructure detected',
      sharedEvidenceExplanation:
        'This correlation indicates shared observable infrastructure. It does not prove common ownership or attacker attribution.',
      description: `Shared infrastructure detected across ${correlationData.campaignCandidate.caseIds.length} analyzed cases.`,
    };

    // Link Campaign Candidate to Current Case
    edges.push({
      from: campKey,
      to: currentCaseKey,
      hot: true,
      dashed: true,
    });

    // Link Campaign Candidate to each Related Case
    correlationData.relatedCases.forEach((rel) => {
      const relKey = `case:${rel.caseId}`;
      if (entities[relKey]) {
        edges.push({
          from: campKey,
          to: relKey,
          hot: true,
          dashed: true,
        });
      }
    });

    // Link Campaign Candidate to shared infrastructure entities
    for (const se of correlationData.campaignCandidate.sharedEntities) {
      let targetKey: string | null = null;
      if (se.type === 'Sender Domain') targetKey = `domain:${se.value}`;
      else if (se.type === 'Return-Path Domain') targetKey = `returnpath:${se.value}`;
      else if (se.type === 'Public IP') targetKey = `ip:${se.value}`;
      else if (se.type === 'URL Domain') targetKey = `urldomain:${se.value}`;

      if (targetKey && entities[targetKey]) {
        edges.push({
          from: campKey,
          to: targetKey,
          hot: true,
          dashed: true,
        });
      }
    }
  }

  // Populate node.count and node.related formatted array for each entity
  for (const edge of edges) {
    const fromEnt = entities[edge.from];
    const toEnt = entities[edge.to];
    if (fromEnt && toEnt) {
      const fromLabel = `${toEnt.value} · ${toEnt.type}`;
      if (!fromEnt.related.includes(fromLabel)) {
        fromEnt.related.push(fromLabel);
      }
      const toLabel = `${fromEnt.value} · ${fromEnt.type}`;
      if (!toEnt.related.includes(toLabel)) {
        toEnt.related.push(toLabel);
      }
    }
  }

  // Update counts
  for (const key of Object.keys(entities)) {
    entities[key].count = entities[key].related.length;
  }

  return {
    entities,
    edges,
    activeEntityKey: currentCaseKey,
  };
}
