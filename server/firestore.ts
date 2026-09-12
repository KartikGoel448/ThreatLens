/**
 * ThreatLens Firestore Persistence Service
 *
 * Persists email forensic cases with domain age intelligence fields:
 * - domainAge
 * - registrationDate
 * - ageInDays
 * - isRecentlyRegistered
 * - lookupStatus
 *
 * Uses lazy initialization and safe fallback to prevent dev crashes when offline.
 */

import { Firestore } from '@google-cloud/firestore';
import type { EmailAnalysisCase } from '../src/types.js';

let dbInstance: Firestore | null = null;
let isFirestoreAvailable: boolean | null = null;

export function getFirestoreDb(): Firestore | null {
  if (isFirestoreAvailable === false) {
    return null;
  }

  if (!dbInstance) {
    try {
      // In Cloud Run / GCP containers, Firestore auto-discovers credentials
      const projectId =
        process.env.GOOGLE_CLOUD_PROJECT ||
        process.env.GCP_PROJECT ||
        process.env.FIREBASE_PROJECT_ID ||
        undefined;

      dbInstance = new Firestore({
        projectId,
        ignoreUndefinedProperties: true,
      });
      isFirestoreAvailable = true;
    } catch (err: any) {
      console.warn('Firestore not configured in environment, operating with in-memory persistence:', err?.message || err);
      isFirestoreAvailable = false;
      return null;
    }
  }

  return dbInstance;
}

/**
 * Persist an email analysis case to Firestore collection 'analyses'
 */
export async function saveAnalysisCaseToFirestore(analysisCase: EmailAnalysisCase): Promise<boolean> {
  const db = getFirestoreDb();
  if (!db) {
    return false;
  }

  try {
    const docRef = db.collection('analyses').doc(analysisCase.caseId);

    // Exact fields specified in ThreatLens Step 2 Step 6:
    const payload = {
      caseId: analysisCase.caseId,
      timestamp: analysisCase.timestamp,
      analyzedAt: analysisCase.analyzedAt,
      subject: analysisCase.subject,
      senderDomain: analysisCase.sender.domain,
      senderEmail: analysisCase.sender.email,
      verdict: analysisCase.verdict,
      riskScore: analysisCase.riskScore,
      riskLevel: analysisCase.riskLevel,
      confidence: analysisCase.confidence,

      // Mandatory Domain Age Intelligence fields:
      domainAge: analysisCase.domainAge,
      registrationDate: analysisCase.registrationDate,
      ageInDays: analysisCase.ageInDays,
      isRecentlyRegistered: analysisCase.isRecentlyRegistered,
      lookupStatus: analysisCase.lookupStatus,

      domainIntelligence: {
        ...analysisCase.domainIntelligence,
        domainAge: analysisCase.domainAge,
        registrationDate: analysisCase.registrationDate,
        ageInDays: analysisCase.ageInDays,
        isRecentlyRegistered: analysisCase.isRecentlyRegistered,
        lookupStatus: analysisCase.lookupStatus,
      },
      authResults: analysisCase.authResults,
      whyFlagged: analysisCase.whyFlagged,
      flaggedUrls: analysisCase.flaggedUrls,
      // Step 3: Structured Relay Trace Information
      relayTrace: {
        hops: (analysisCase.relayTrace || []).map((hop) => {
          const h: Record<string, any> = {
            hopNumber: hop.hopNumber,
            hostname: hop.host,
            ip: hop.ip,
          };
          if (hop.sendingHostname && hop.sendingHostname !== 'Unavailable') {
            h.sendingHostname = hop.sendingHostname;
          }
          if (hop.ipType) {
            h.ipType = hop.ipType;
          }
          if (hop.timestamp && hop.timestamp !== 'Unavailable') {
            h.timestamp = hop.timestamp;
          }
          if (hop.timezone && hop.timezone !== 'Unavailable') {
            h.timezone = hop.timezone;
          }
          if (hop.delayFromPreviousHop) {
            h.delayFromPreviousHop = hop.delayFromPreviousHop;
          }
          if (hop.geolocation) {
            const g: Record<string, any> = {
              status: hop.geolocation.status,
            };
            if (hop.geolocation.country) g.country = hop.geolocation.country;
            if (hop.geolocation.region) g.region = hop.geolocation.region;
            if (hop.geolocation.city) g.city = hop.geolocation.city;
            if (typeof hop.geolocation.latitude === 'number') g.latitude = hop.geolocation.latitude;
            if (typeof hop.geolocation.longitude === 'number') g.longitude = hop.geolocation.longitude;
            if (hop.geolocation.isp) g.isp = hop.geolocation.isp;
            if (hop.geolocation.asn) g.asn = hop.geolocation.asn;
            h.geolocation = g;
          }
          if (hop.response && hop.response !== 'SMTP response unavailable') {
            h.response = hop.response;
          }
          return h;
        }),
      },
      rawRelayHops: analysisCase.relayTrace,
      // Step 4: Structured AI Content Threat Analysis
      aiContentAnalysis: analysisCase.aiContentAnalysis
        ? {
            available: analysisCase.aiContentAnalysis.contentAnalysisAvailable,
            findings: analysisCase.aiContentAnalysis.findings.map((f) => ({
              category: f.category,
              severity: f.severity,
              confidence: f.confidence,
              evidence: f.evidence,
            })),
            overallAssessment: analysisCase.aiContentAnalysis.overallAssessment,
          }
        : {
            available: false,
            findings: [],
            overallAssessment: 'Email body unavailable — content-based analysis could not be performed.',
          },
      // Step 5: Real Investigation Graph & Campaign Correlation Data
      correlation: analysisCase.correlation
        ? {
            relatedCases: analysisCase.correlation.relatedCases.map((rc) => ({
              caseId: rc.caseId,
              subject: rc.subject,
              verdict: rc.verdict,
              riskScore: rc.riskScore,
              timestamp: rc.timestamp,
              sharedEntities: rc.sharedEntities,
            })),
            campaignCandidate: {
              detected: analysisCase.correlation.campaignCandidate.detected,
              confidence: analysisCase.correlation.campaignCandidate.confidence,
              reason: analysisCase.correlation.campaignCandidate.reason,
              sharedEntities: analysisCase.correlation.campaignCandidate.sharedEntities,
              caseIds: analysisCase.correlation.campaignCandidate.caseIds,
            },
            totalAnalyzedCasesCount: analysisCase.correlation.totalAnalyzedCasesCount,
          }
        : null,
      graph: analysisCase.graph || null,
      // Step 6: Forensic Report Metadata & Integrity Hash
      forensicReport: analysisCase.forensicReport
        ? {
            generatedAt: analysisCase.forensicReport.generatedAt,
            canonicalHash: analysisCase.forensicReport.canonicalHash,
            hashAlgorithm: 'SHA-256',
            disclaimer: analysisCase.forensicReport.disclaimer,
          }
        : null,
      updatedAt: new Date().toISOString(),
    };

    await docRef.set(payload, { merge: true });
    console.log(`[Firestore] Case ${analysisCase.caseId} successfully synced to collection 'analyses'`);
    return true;
  } catch (err: any) {
    console.warn(`[Firestore] Sync skipped for case ${analysisCase.caseId}:`, err?.message || err);
    return false;
  }
}

/**
 * Retrieve an email analysis case from Firestore collection 'analyses'
 */
export async function getAnalysisCaseFromFirestore(caseId: string): Promise<any | null> {
  const db = getFirestoreDb();
  if (!db) return null;

  try {
    const docRef = db.collection('analyses').doc(caseId);
    const docSnap = await docRef.get();
    if (!docSnap.exists) {
      return null;
    }
    return docSnap.data();
  } catch (err: any) {
    console.warn(`[Firestore] Error fetching case ${caseId}:`, err?.message || err);
    return null;
  }
}

/**
 * Retrieve all analyzed case summaries from Firestore collection 'analyses'
 * for real cross-case correlation and investigation graph generation.
 * Limits fields to structured entities and metadata (excludes large raw email bodies).
 */
export async function getAllAnalyzedCasesFromFirestore(): Promise<any[]> {
  const db = getFirestoreDb();
  if (!db) return [];

  try {
    const snapshot = await db.collection('analyses').limit(100).get();
    if (snapshot.empty) {
      return [];
    }
    return snapshot.docs.map((doc) => doc.data());
  } catch (err: any) {
    console.warn('[Firestore] Error fetching analyzed cases for correlation:', err?.message || err);
    return [];
  }
}

