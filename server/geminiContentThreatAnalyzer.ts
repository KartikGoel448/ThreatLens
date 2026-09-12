/**
 * ThreatLens AI Content Threat Intelligence Engine
 * Powered by Gemini 3.8 Flash
 *
 * Strictly adheres to the Evidence Boundary:
 * - Evaluates ONLY the actual extracted email text content, subject, and link contexts.
 * - Does NOT invent, hallucinate, or override technical headers (SPF, DKIM, DMARC, IP, WHOIS, DNS, Relay Trace).
 * - Identifies:
 *    A. Urgency / pressure
 *    B. Credential harvesting
 *    C. Suspicious link pressure
 *    D. Impersonation / brand spoofing language
 *    E. Financial / sensitive-information requests
 * - Outputs structured JSON.
 * - Integrates into risk engine with a maximum +15 point contribution (transparently capped at 100).
 */

import { GoogleGenAI, Type } from '@google/genai';
import type { AiContentAnalysis, AiContentFinding, EvidenceItem } from '../src/types.js';
import type { ExtractedEmailContent } from './emailContentExtractor.js';

function getGeminiClient(): GoogleGenAI | null {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey || apiKey === 'MY_GEMINI_API_KEY') {
    return null;
  }
  return new GoogleGenAI({
    apiKey,
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-build',
      },
    },
  });
}

/**
 * Standard categories recognized by ThreatLens
 */
export const ALLOWED_CATEGORIES = [
  'Urgency / Pressure',
  'Credential Harvesting',
  'Suspicious Link Pressure',
  'Impersonation',
  'Financial Request',
  'Sensitive Information Request',
] as const;

/**
 * Perform server-side Gemini 3.8 Flash content analysis on actual extracted email content
 */
export async function analyzeEmailContentWithGemini(
  content: ExtractedEmailContent
): Promise<AiContentAnalysis> {
  // 1. If email body is unavailable, return standardized response without calling Gemini
  if (!content.bodyAvailable || !content.plainTextBody.trim()) {
    return {
      contentAnalysisAvailable: false,
      findings: [],
      overallAssessment: 'Email body unavailable — content-based analysis could not be performed.',
    };
  }

  const gemini = getGeminiClient();
  if (!gemini) {
    console.warn('[Gemini] GEMINI_API_KEY not configured or placeholder detected; applying deterministic content heuristic fallback');
    return runDeterministicContentFallback(content, false);
  }

  try {
    const prompt = `You are ThreatLens AI Content Threat Intelligence Engine.
You analyze ONLY the supplied email text content, subject line, and extracted link context to identify social-engineering and phishing indicators.

CRITICAL INSTRUCTIONS & STRICT BOUNDARIES:
1. Base your findings EXCLUSIVELY on the actual text supplied below.
2. DO NOT invent or evaluate technical headers (SPF, DKIM, DMARC, IP addresses, Received headers, domain age, DNS). The deterministic engine handles technical evidence.
3. Identify evidence strictly across these threat categories:
   - Urgency / Pressure (urgent action requests, deadlines, threats of account suspension, fear-based language, pressure to act immediately)
   - Credential Harvesting (requests or prompts for passwords, login credentials, account verification, security verification, authentication info)
   - Suspicious Link Pressure (encouraging recipient to click a link to verify account, reset credentials, resolve issue, claim benefit, make payment)
   - Impersonation (claims to represent a company, bank, payment provider, cloud service, administrator, executive, or security team. Only identify a specific brand when actual email text supports it)
   - Financial Request (requests involving payments, invoices, wire transfers, escrow, bank accounts, or financial settlement)
   - Sensitive Information Request (soliciting confidential documents, employee data, credentials, or proprietary files)
4. For each finding:
   - category: One of the 6 categories above
   - severity: "low" | "medium" | "high"
   - confidence: Integer 0-100
   - evidence: A concise paraphrase of the actual message evidence (do NOT quote large text blocks)
5. If there are NO meaningful phishing or social-engineering indicators in the text, return findings as an empty array [] and overallAssessment: "No significant phishing or social-engineering indicators were detected in the supplied email content."

SUPPLIED EMAIL CONTENT:
- Subject: ${content.subject}
- From: ${content.from}
- Return-Path: ${content.returnPath || 'Unavailable'}

Extracted URLs & Surrounding Visible Text Context:
${
  content.extractedUrls.length > 0
    ? content.extractedUrls
        .slice(0, 10)
        .map((u) => `- URL: ${u.url}${u.surroundingText ? ` (Context: "${u.surroundingText}")` : ''}`)
        .join('\n')
    : 'No embedded URLs present.'
}

Email Body Text:
"""
${content.plainTextBody.slice(0, 7000)}
"""`;

    // Timeout guard (8 seconds max)
    const timeoutPromise = new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error('Gemini content analysis timed out after 8000ms')), 8000)
    );

    const apiCallPromise = gemini.models.generateContent({
      model: 'gemini-3.8-flash',
      contents: prompt,
      config: {
        responseMimeType: 'application/json',
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            contentAnalysisAvailable: {
              type: Type.BOOLEAN,
              description: 'Must be true when content was analyzed',
            },
            findings: {
              type: Type.ARRAY,
              items: {
                type: Type.OBJECT,
                properties: {
                  category: {
                    type: Type.STRING,
                    description: 'Urgency / Pressure, Credential Harvesting, Suspicious Link Pressure, Impersonation, Financial Request, or Sensitive Information Request',
                  },
                  severity: {
                    type: Type.STRING,
                    description: 'low, medium, or high',
                  },
                  confidence: {
                    type: Type.INTEGER,
                    description: 'Integer between 0 and 100',
                  },
                  evidence: {
                    type: Type.STRING,
                    description: 'Short paraphrase of the actual message evidence',
                  },
                },
                required: ['category', 'severity', 'confidence', 'evidence'],
              },
            },
            overallAssessment: {
              type: Type.STRING,
              description: 'Short plain-language assessment of the supplied email content',
            },
          },
          required: ['contentAnalysisAvailable', 'findings', 'overallAssessment'],
        },
      },
    });

    const response = await Promise.race([apiCallPromise, timeoutPromise]);
    const jsonText = response.text?.trim();

    if (jsonText) {
      const parsed = JSON.parse(jsonText);
      const findings: AiContentFinding[] = Array.isArray(parsed.findings)
        ? parsed.findings
            .filter((f: any) => f && typeof f.category === 'string' && typeof f.evidence === 'string')
            .map((f: any) => ({
              category: normalizeCategory(f.category),
              severity: ['low', 'medium', 'high'].includes(f.severity?.toLowerCase())
                ? (f.severity.toLowerCase() as 'low' | 'medium' | 'high')
                : 'medium',
              confidence:
                typeof f.confidence === 'number' && !isNaN(f.confidence)
                  ? Math.max(0, Math.min(100, Math.round(f.confidence)))
                  : 80,
              evidence: String(f.evidence).slice(0, 300),
            }))
        : [];

      let overallAssessment = typeof parsed.overallAssessment === 'string' && parsed.overallAssessment.trim().length > 0
        ? parsed.overallAssessment.trim()
        : findings.length === 0
        ? 'No significant phishing or social-engineering indicators were detected in the supplied email content.'
        : `Identified ${findings.length} social-engineering and persuasion indicators in the email content.`;

      return {
        contentAnalysisAvailable: true,
        findings,
        overallAssessment,
      };
    }
  } catch (err: any) {
    console.warn('[Gemini] Content analysis error or timeout, engaging deterministic heuristic fallback:', err?.message || err);
  }

  // Graceful fallback to deterministic heuristic analysis
  return runDeterministicContentFallback(content, true);
}

/**
 * Normalizes category names to standard ThreatLens taxonomy
 */
function normalizeCategory(rawCategory: string): string {
  const lower = rawCategory.toLowerCase();
  if (lower.includes('urgent') || lower.includes('pressure') || lower.includes('deadline')) {
    return 'Urgency / Pressure';
  }
  if (lower.includes('credential') || lower.includes('password') || lower.includes('login') || lower.includes('verify account')) {
    return 'Credential Harvesting';
  }
  if (lower.includes('link') || lower.includes('click') || lower.includes('url')) {
    return 'Suspicious Link Pressure';
  }
  if (lower.includes('impersonat') || lower.includes('brand') || lower.includes('spoof') || lower.includes('executive')) {
    return 'Impersonation';
  }
  if (lower.includes('financial') || lower.includes('wire') || lower.includes('payment') || lower.includes('invoice') || lower.includes('escrow')) {
    return 'Financial Request';
  }
  if (lower.includes('sensitive') || lower.includes('document') || lower.includes('confidential')) {
    return 'Sensitive Information Request';
  }
  return rawCategory.slice(0, 40);
}

/**
 * Deterministic heuristic fallback when Gemini API is unavailable or times out
 */
export function runDeterministicContentFallback(
  content: ExtractedEmailContent,
  wasAiAttempted = false
): AiContentAnalysis {
  if (!content.bodyAvailable) {
    return {
      contentAnalysisAvailable: false,
      findings: [],
      overallAssessment: 'Email body unavailable — content-based analysis could not be performed.',
    };
  }

  const combined = `${content.subject} ${content.plainTextBody}`.toLowerCase();
  const findings: AiContentFinding[] = [];

  // 1. Urgency / Pressure check
  if (
    combined.includes('immediate') ||
    combined.includes('24 hours') ||
    combined.includes('within 24') ||
    combined.includes('account suspension') ||
    combined.includes('suspended') ||
    combined.includes('urgent') ||
    combined.includes('without delay')
  ) {
    findings.push({
      category: 'Urgency / Pressure',
      severity: 'high',
      confidence: 85,
      evidence: 'Message emphasizes tight deadlines and threat of service termination or urgent compliance.',
    });
  }

  // 2. Credential Harvesting check
  if (
    combined.includes('verify your credentials') ||
    combined.includes('verify your account') ||
    combined.includes('password reset') ||
    combined.includes('sign-in from an unknown device') ||
    combined.includes('unusual activity detected')
  ) {
    findings.push({
      category: 'Credential Harvesting',
      severity: 'high',
      confidence: 90,
      evidence: 'Solicits immediate login verification and security credentials under guise of security alert.',
    });
  }

  // 3. Suspicious Link Pressure check
  if (
    content.extractedUrls.length > 0 &&
    (combined.includes('click here') ||
      combined.includes('verify:') ||
      combined.includes('review account') ||
      combined.includes('log in to update'))
  ) {
    findings.push({
      category: 'Suspicious Link Pressure',
      severity: 'medium',
      confidence: 80,
      evidence: 'Directs recipient to click embedded web hyperlinks to resolve security or account status.',
    });
  }

  // 4. Financial Request check
  if (
    combined.includes('wire transfer') ||
    combined.includes('escrow') ||
    combined.includes('settlement') ||
    combined.includes('payment of $') ||
    combined.includes('invoice') ||
    combined.includes('remittance')
  ) {
    findings.push({
      category: 'Financial Request',
      severity: 'high',
      confidence: 88,
      evidence: 'Requests urgent execution of financial wire transfer or escrow payment settlement.',
    });
  }

  // 5. Impersonation check
  if (
    combined.includes('ceo') ||
    combined.includes('chief executive') ||
    combined.includes('security support team') ||
    combined.includes('account security') ||
    combined.includes('helpdesk administrator')
  ) {
    findings.push({
      category: 'Impersonation',
      severity: 'medium',
      confidence: 75,
      evidence: 'Uses authoritative administrative or executive identity phrasing to demand compliance.',
    });
  }

  const overallAssessment =
    findings.length > 0
      ? `Heuristic content evaluation detected ${findings.length} social-engineering and persuasion indicators.`
      : 'No significant phishing or social-engineering indicators were detected in the supplied email content.';

  return {
    contentAnalysisAvailable: true,
    findings,
    overallAssessment: wasAiAttempted
      ? `${overallAssessment} (Deterministic fallback applied due to AI service timeout/unavailability).`
      : overallAssessment,
  };
}

/**
 * Calculates risk score contribution and transparent evidence item according to Step 4 mandate:
 * - Suspicious content finding: +15 maximum
 * - Transparent in score breakdown
 * - Cap the total risk score at 100
 * - Do not add +15 repeatedly for every individual finding
 * - If Gemini fails, times out, or body is unavailable: do NOT increase risk merely because of missing AI
 */
export function calculateAiScoreContribution(
  analysis: AiContentAnalysis
): { points: number; evidenceItem: EvidenceItem } {
  if (!analysis.contentAnalysisAvailable) {
    return {
      points: 0,
      evidenceItem: {
        text: 'AI-Assisted Content Analysis: Email body unavailable — content-based analysis could not be performed (+0 risk points)',
        type: 'warn',
      },
    };
  }

  if (analysis.findings.length === 0) {
    return {
      points: 0,
      evidenceItem: {
        text: 'AI-Assisted Content Analysis: No significant phishing or social-engineering indicators detected (+0 risk points)',
        type: 'ok',
      },
    };
  }

  // Max +15 points rule
  const hasHigh = analysis.findings.some((f) => f.severity === 'high');
  const hasMedium = analysis.findings.some((f) => f.severity === 'medium');

  const points = hasHigh ? 15 : hasMedium ? 10 : 5;
  const categoriesText = Array.from(new Set(analysis.findings.map((f) => f.category)))
    .slice(0, 3)
    .join(', ');

  return {
    points,
    evidenceItem: {
      text: `AI-Assisted Content Analysis: Social-engineering indicators detected (${categoriesText}) [+${points} risk points]`,
      type: 'fail',
    },
  };
}
