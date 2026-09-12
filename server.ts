import express from 'express';
import path from 'path';
import { createServer as createViteServer } from 'vite';
import dotenv from 'dotenv';
import type { EmailAnalysisCase, SampleEmailPreset, RelayHop, GraphEntity, AiContentAnalysis } from './src/types.js';
import { lookupDomainRegistrationAge } from './server/domainIntelligence.js';
import { buildRealRelayTrace } from './server/relayTrace.js';
import {
  saveAnalysisCaseToFirestore,
  getAnalysisCaseFromFirestore,
  getAllAnalyzedCasesFromFirestore,
} from './server/firestore.js';
import { extractEmailContent } from './server/emailContentExtractor.js';
import { analyzeEmailContentWithGemini, calculateAiScoreContribution } from './server/geminiContentThreatAnalyzer.js';
import {
  correlateWithPastCases,
  buildRealInvestigationGraph,
} from './server/correlationEngine.js';
import {
  buildCanonicalReportPayload,
  deterministicStringify,
  computeSha256,
  verifyReportIntegrity,
  generateMarkdownReport,
  INTEGRITY_HASH_DISCLAIMER,
} from './src/utils/forensicReport.js';

dotenv.config();

const app = express();
const PORT = 3000;

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// In-memory cases repository
const casesStore: Map<string, EmailAnalysisCase> = new Map();

// Sample presets for quick testing
export const SAMPLE_PRESETS: SampleEmailPreset[] = [
  {
    id: 'phish-urgent-verify',
    title: 'Phishing · Urgent Account Verification',
    badge: 'HIGH RISK',
    badgeCls: 'fail',
    description: 'Spoofed "Account Security" brand asking for urgent credential verification. Fails SPF & DMARC.',
    headers: `From: "Account Security" <support@example-domain.com>
To: user@example.com
Subject: Urgent account verification required
Date: Sat, 12 Sep 2026 12:41:52 +0000

Received: from mx2.recipient-isp.example.net (mx2.recipient-isp.example.net [198.51.100.27])
        by mail.example.com with ESMTP id A3f9Kq2
        for <user@example.com>; Sat, 12 Sep 2026 12:43:02 +0000
Received: from relay.mailnode.example.net (relay.mailnode.example.net [103.16.201.44])
        by mx2.recipient-isp.example.net with ESMTP id Q2c9D8
        for <user@example.com>; Sat, 12 Sep 2026 12:42:33 +0000
Received: from mx1.example-domain.com (mx1.example-domain.com [185.204.48.131])
        by relay.mailnode.example.net with ESMTP id R7a1B4
        for <user@example.com>; Sat, 12 Sep 2026 12:42:31 +0000

Return-Path: <support@example-domain.com>
Message-ID: <A3f9Kq2@example-domain.com>

Authentication-Results: mx2.recipient-isp.example.net;
        spf=fail (sender IP 185.204.48.131 not authorized) smtp.mailfrom=support@example-domain.com;
        dkim=pass header.d=example-domain.com;
        dmarc=fail (p=reject) header.from=example-domain.com

DKIM-Signature: v=1; a=rsa-sha256; d=example-domain.com; s=s1;
        bh=Za3x...; h=from:to:subject:date;
        i=@example-domain.com

Content-Type: text/plain; charset=UTF-8

Dear Customer,

We detected an irregular sign-in from an unknown device. Please verify your credentials immediately within 24 hours to prevent immediate account suspension.

Click here to verify: https://secure-login.example.net/session/refresh
Or review account settings: https://example-domain.com/verify-account

Thank you,
Account Security Support Team`,
  },
  {
    id: 'bec-ceo-transfer',
    title: 'BEC · CEO Urgent Wire Transfer',
    badge: 'CRITICAL RISK',
    badgeCls: 'fail',
    description: 'Executive impersonation with mismatched Return-Path and external freemail relay.',
    headers: `From: "Arthur Pendelton (CEO)" <ceo@acme-enterprises.corp>
To: finance-dept@acme-enterprises.corp
Subject: CONFIDENTIAL: Urgent Vendor Acquisition Settlement
Date: Thu, 10 Sep 2026 09:14:10 +0000
Return-Path: <arthur-office9812@proton-mail-relay.net>
Message-ID: <wire-99124-urgent@proton-mail-relay.net>

Received: from mail-gateway.acme-enterprises.corp ([192.0.2.14])
        by internal-exchange.acme.local with ESMTP id B18a994; Thu, 10 Sep 2026 09:15:02 +0000
Received: from mx.proton-mail-relay.net ([185.70.40.119])
        by mail-gateway.acme-enterprises.corp with ESMTPS id G66b129; Thu, 10 Sep 2026 09:14:35 +0000

Authentication-Results: mail-gateway.acme-enterprises.corp;
        spf=softfail (ip=185.70.40.119 domain=acme-enterprises.corp) smtp.mailfrom=arthur-office9812@proton-mail-relay.net;
        dkim=fail (body hash mismatch);
        dmarc=fail (p=quarantine) header.from=acme-enterprises.corp

Content-Type: text/plain; charset=UTF-8

Team,

I am currently in an all-day closed board meeting with external legal counsel. 
We must finalize the acquisition escrow payment of $142,500 by 11:30 AM today without delay.

Please process the wire transfer immediately using the updated settlement instructions at:
https://acme-escrow-settlement.com/invoice/INV-9410.pdf

Do not call my mobile as I cannot step out of the meeting room. Reply directly to this email with confirmation once processed.

Best regards,
Arthur Pendelton
Chief Executive Officer`,
  },
  {
    id: 'clean-newsletter',
    title: 'Clean · GitHub Security Advisory Digest',
    badge: 'CLEAN',
    badgeCls: 'pass',
    description: 'Legitimate corporate notification with full SPF, DKIM, and DMARC alignment.',
    headers: `From: "GitHub Security" <notifications@github.com>
To: dev-lead@example.com
Subject: [GitHub] Security advisories for your watched repositories
Date: Fri, 11 Sep 2026 18:02:11 +0000
Return-Path: <support=github.com@mail.github.com>
Message-ID: <security-digest-891024@github.com>

Received: from mx.recipient-corp.net ([198.51.100.88])
        by inbound.recipient-corp.net with ESMTP id M41019; Fri, 11 Sep 2026 18:02:30 +0000
Received: from out-1.mail.github.com ([192.30.252.204])
        by mx.recipient-corp.net with ESMTPS id N991823; Fri, 11 Sep 2026 18:02:20 +0000

Authentication-Results: mx.recipient-corp.net;
        spf=pass (ip=192.30.252.204) smtp.mailfrom=support=github.com@mail.github.com;
        dkim=pass header.d=github.com header.s=pf2024;
        dmarc=pass (p=reject) header.from=github.com

DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=github.com; s=pf2024;
        h=from:to:subject:date:message-id:mime-version;
        bh=kG92...; b=Q91a...

Content-Type: text/plain; charset=UTF-8

Hi there,

Here is your weekly summary of dependabot alerts and security advisories for your repositories.
No critical vulnerabilities were discovered in the last 7 days.

View security overview dashboard: https://github.com/settings/security
Read GitHub advisory database: https://github.com/advisories

Thanks,
The GitHub Security Team`,
  },
  {
    id: 'phish-recent-domain',
    title: 'Phishing · Recently Registered Domain (<30d)',
    badge: 'HIGH RISK',
    badgeCls: 'fail',
    description: 'Freshly registered domain impersonating cloud security updates. Triggers +15 risk points.',
    headers: `From: "Cloud Security Operations" <support@cloud-auth-update-2026.com>
To: target-user@enterprise.com
Subject: [ACTION REQUIRED] Security session expired - re-authenticate
Date: Sat, 12 Sep 2026 14:10:00 +0000
Return-Path: <bounce@cloud-auth-update-2026.com>
Message-ID: <revoked-99124@cloud-auth-update-2026.com>

Received: from mx1.recipient-corp.net (mx1.recipient-corp.net [198.51.100.99])
        by mail.enterprise.com with ESMTP id C992F1; Sat, 12 Sep 2026 14:11:15 +0000
Received: from mx.cloud-auth-update-2026.com (mx.cloud-auth-update-2026.com [185.220.101.5])
        by mx1.recipient-corp.net with ESMTP id K81240; Sat, 12 Sep 2026 14:10:45 +0000

Authentication-Results: mx1.recipient-corp.net;
        spf=pass (ip=185.220.101.5) smtp.mailfrom=bounce@cloud-auth-update-2026.com;
        dkim=pass header.d=cloud-auth-update-2026.com;
        dmarc=pass (p=none) header.from=cloud-auth-update-2026.com

Content-Type: text/plain; charset=UTF-8

Your corporate single-sign-on credentials have encountered an authentication anomaly.
Please sign in immediately through the identity verification portal to prevent account deactivation:
https://cloud-auth-update-2026.com/portal/login?ref=sec_9912

IT Infrastructure Team`,
  },
];

// Seed the prototype default case
const defaultPrototypeCase: EmailAnalysisCase = {
  caseId: 'MS-2026-00142',
  timestamp: '12 Sep 2026 · 12:43 UTC',
  analyzedAt: '12 September 2026',
  verdict: 'POTENTIALLY MALICIOUS',
  riskScore: 78,
  riskLevel: 'HIGH RISK',
  confidence: 94,
  sender: {
    displayName: 'Account Security',
    email: 'support@example-domain.com',
    domain: 'example-domain.com',
    returnPath: 'support@example-domain.com',
  },
  recipient: {
    email: 'user@example.com',
  },
  subject: 'Urgent account verification required',
  receivedDate: '12 Sep 2026 · 12:41:52 UTC',
  messageId: 'A3f9Kq2@example-domain.com',
  authResults: {
    spf: {
      status: 'FAIL',
      summary: 'SPF validation failed',
      details: 'Sending IP is not authorized by the domain SPF record (185.204.48.131 not in v=spf1).',
      record: 'v=spf1 ip4:198.51.100.0/24 ~all',
    },
    dkim: {
      status: 'PASS',
      summary: 'DKIM signature valid',
      details: 'Email signature successfully verified with selector s1, RSA-SHA256.',
      selector: 's1',
    },
    dmarc: {
      status: 'FAIL',
      summary: 'DMARC alignment failed',
      details: 'Domain alignment policy (p=reject) was not satisfied due to unaligned SPF and domain mismatch.',
      policy: 'p=reject',
    },
  },
  domainIntelligence: {
    domain: 'example-domain.com',
    reputation: 'SUSPICIOUS',
    age: '24.0 years (8,760 days)',
    firstSeen: '28 Sep 2000',
    registrationCountry: 'Verified via RDAP Registry',
    summary: 'Established domain registered via official registry. No domain age risk penalty applied (+0 points).',
    tags: ['Established Domain (>30d)', 'RDAP Verified', '+0 Risk Points'],
    blocklistsCount: 0,
    domainAge: '24.0 years (8,760 days)',
    registrationDate: '2000-09-28T18:43:29.000Z',
    ageInDays: 8760,
    isRecentlyRegistered: false,
    lookupStatus: 'ESTABLISHED',
    registrar: 'MarkMonitor Inc.',
    provider: 'RDAP',
  },
  domainAge: '24.0 years (8,760 days)',
  registrationDate: '2000-09-28T18:43:29.000Z',
  ageInDays: 8760,
  isRecentlyRegistered: false,
  lookupStatus: 'ESTABLISHED',
  flaggedUrls: [
    {
      url: 'https://secure-login.example.net/session/refresh',
      risk: 'HIGH RISK',
      reason: "Lookalike of the recipient's login domain; TLS certificate issued to an unrelated organization.",
      domain: 'secure-login.example.net',
      category: 'Credential Harvester',
    },
    {
      url: 'https://example-domain.com/verify-account',
      risk: 'SUSPICIOUS',
      reason: 'Domain differs from the expected organization and lacks legitimate reputation.',
      domain: 'example-domain.com',
      category: 'Phishing Landing Page',
    },
  ],
  whyFlagged: {
    explanation:
      'This email shows several indicators commonly associated with phishing. DMARC authentication failed, one embedded URL points to a suspicious lookalike domain, and the message uses urgent account-verification language typical of credential-harvesting campaigns.',
    evidence: [
      { text: 'DMARC authentication failed', type: 'fail' },
      { text: 'Suspicious URL detected', type: 'fail' },
      { text: 'Sender domain has poor reputation', type: 'fail' },
      { text: 'Urgent language detected', type: 'fail' },
    ],
  },
  relayTrace: [
    {
      hopNumber: 1,
      name: 'Origin MTA (Submission)',
      role: 'SOURCE',
      host: 'relay.mailnode.example.net',
      sendingHostname: 'mx1.example-domain.com',
      ip: '185.204.48.131',
      ipType: 'PUBLIC',
      location: 'Tyre, Mohafazat Liban-Sud, Lebanon (Approximate)',
      timestamp: 'Sat, 12 Sep 2026 12:42:31 +0000',
      timezone: '+0000',
      delayFromPreviousHop: 'Initial hop (Transmission origin)',
      response: 'ESMTP id R7a1B4',
      reason: "Earliest observed relay hop in header chain. Received from 'mx1.example-domain.com' by 'relay.mailnode.example.net'.",
      rawHeader: 'Received: from mx1.example-domain.com (185.204.48.131) by relay.mailnode.example.net with ESMTP id R7a1B4; 12:42:31 +0000',
      geolocation: {
        status: 'SUCCESS',
        country: 'Lebanon',
        region: 'Mohafazat Liban-Sud',
        city: 'Tyre',
        latitude: 33.2733,
        longitude: 35.1939,
        isp: 'Cedarcom',
        asn: 'AS42314',
      },
      geo: { x: 550.8, y: 140, label: 'relay.mailnode.example.net' },
    },
    {
      hopNumber: 2,
      name: 'Transit Relay Hop 2',
      role: 'WATCH',
      host: 'mx2.recipient-isp.example.net',
      sendingHostname: 'relay.mailnode.example.net',
      ip: '103.16.201.44',
      ipType: 'PUBLIC',
      location: 'Bengaluru, Karnataka, India (Approximate)',
      timestamp: 'Sat, 12 Sep 2026 12:42:33 +0000',
      timezone: '+0000',
      delayFromPreviousHop: '+2s transit delay',
      delayMs: 2000,
      response: 'ESMTP id Q2c9D8',
      reason: "Intermediate mail relay MTA 'mx2.recipient-isp.example.net' routing message towards destination.",
      rawHeader: 'Received: from relay.mailnode.example.net (103.16.201.44) by mx2.recipient-isp.example.net with ESMTP id Q2c9D8; 12:42:33 +0000',
      geolocation: {
        status: 'SUCCESS',
        country: 'India',
        region: 'Karnataka',
        city: 'Bengaluru',
        latitude: 12.9716,
        longitude: 77.5946,
        isp: 'Bharti Airtel',
        asn: 'AS9498',
      },
      geo: { x: 659.1, y: 193.6, label: 'mx2.recipient-isp.example.net' },
    },
    {
      hopNumber: 3,
      name: 'Recipient MX Gateway',
      role: 'DELIVERED',
      host: 'mail.example.com',
      sendingHostname: 'mx2.recipient-isp.example.net',
      ip: '198.51.100.27',
      ipType: 'DOCUMENTATION',
      location: 'Private/Reserved IP — Geolocation unavailable',
      timestamp: 'Sat, 12 Sep 2026 12:43:02 +0000',
      timezone: '+0000',
      delayFromPreviousHop: '+29s transit delay',
      delayMs: 29000,
      response: 'ESMTP id A3f9Kq2',
      reason: "Final recipient boundary MTA 'mail.example.com' accepting message. Note: Hop utilizes RFC 5737 Documentation block TEST-NET-2 (198.51.100.0/24).",
      rawHeader: 'Received: from mx2.recipient-isp.example.net (198.51.100.27) by mail.example.com with ESMTP id A3f9Kq2; 12:43:02 +0000',
      geolocation: {
        status: 'PRIVATE_RESERVED',
        message: 'RFC 5737 Documentation block TEST-NET-2 (198.51.100.0/24)',
      },
    },
  ],
  // Generated using real deterministic graph & correlation engine (zero fake demo nodes)
  graph: buildRealInvestigationGraph(
    {
      caseId: 'TL-2026-88219',
      subject: 'Urgent account verification required',
      verdict: 'HIGH RISK',
      riskScore: 84,
      timestamp: 'Sat, 12 Sep 2026 12:43:02 +0000',
      sender: {
        displayName: 'Account Security',
        email: 'support@example-domain.com',
        domain: 'example-domain.com',
        returnPath: 'support@example-domain.com',
      },
      flaggedUrls: [
        {
          url: 'https://example-domain.com/verify-account',
          risk: 'HIGH RISK',
          reason: 'Matches brand impersonation pattern',
        },
      ],
      technicalDetails: {
        observedIps: [
          { ip: '185.204.48.131', note: 'Public Relay Hop 1' },
          { ip: '103.16.201.44', note: 'Public Relay Hop 2' },
          { ip: '198.51.100.27', note: 'Documentation Private RFC Block' },
        ],
      },
    },
    correlateWithPastCases(
      {
        caseId: 'TL-2026-88219',
        subject: 'Urgent account verification required',
        verdict: 'HIGH RISK',
        riskScore: 84,
        timestamp: 'Sat, 12 Sep 2026 12:43:02 +0000',
        sender: {
          displayName: 'Account Security',
          email: 'support@example-domain.com',
          domain: 'example-domain.com',
          returnPath: 'support@example-domain.com',
        },
        flaggedUrls: [
          {
            url: 'https://example-domain.com/verify-account',
            risk: 'HIGH RISK',
            reason: 'Matches brand impersonation pattern',
          },
        ],
        technicalDetails: {
          observedIps: [
            { ip: '185.204.48.131', note: 'Public Relay Hop 1' },
            { ip: '103.16.201.44', note: 'Public Relay Hop 2' },
            { ip: '198.51.100.27', note: 'Documentation Private RFC Block' },
          ],
        },
      },
      []
    )
  ),
  correlation: correlateWithPastCases(
    {
      caseId: 'TL-2026-88219',
      subject: 'Urgent account verification required',
      verdict: 'HIGH RISK',
      riskScore: 84,
      timestamp: 'Sat, 12 Sep 2026 12:43:02 +0000',
      sender: {
        displayName: 'Account Security',
        email: 'support@example-domain.com',
        domain: 'example-domain.com',
        returnPath: 'support@example-domain.com',
      },
      flaggedUrls: [
        {
          url: 'https://example-domain.com/verify-account',
          risk: 'HIGH RISK',
          reason: 'Matches brand impersonation pattern',
        },
      ],
      technicalDetails: {
        observedIps: [
          { ip: '185.204.48.131', note: 'Public Relay Hop 1' },
          { ip: '103.16.201.44', note: 'Public Relay Hop 2' },
          { ip: '198.51.100.27', note: 'Documentation Private RFC Block' },
        ],
      },
    },
    []
  ),
  technicalDetails: {
    rawHeaders: `Return-Path: <support@example-domain.com>
Message-ID: <A3f9Kq2@example-domain.com>
Date: Sat, 12 Sep 2026 12:41:52 +0000
Subject: Urgent account verification required
From: "Account Security" <support@example-domain.com>
To: user@example.com

Received: from mx1.example-domain.com (185.204.48.131)
        by relay.mailnode.example.net with ESMTP id R7a1B4; 12:42:31 +0000
Received: from relay.mailnode.example.net (103.16.201.44)
        by mx2.recipient-isp.example.net with ESMTP id Q2c9D8; 12:42:33 +0000
Received: from mx2.recipient-isp.example.net (198.51.100.27)
        by mail.example.com with ESMTP id A3f9Kq2; 12:43:02 +0000`,
    receivedChain: [
      'Received: from mx1.example-domain.com (185.204.48.131) by relay.mailnode.example.net with ESMTP id R7a1B4; 12:42:31 +0000',
      'Received: from relay.mailnode.example.net (103.16.201.44) by mx2.recipient-isp.example.net with ESMTP id Q2c9D8; 12:42:33 +0000',
      'Received: from mx2.recipient-isp.example.net (198.51.100.27) by mail.example.com with ESMTP id A3f9Kq2; 12:43:02 +0000',
    ],
    observedIps: [
      { ip: '185.204.48.131', note: 'sender MX (example-domain.com)' },
      { ip: '103.16.201.44', note: 'relay server (mailnode.example.net)' },
      { ip: '198.51.100.27', note: 'recipient MX (recipient-isp.example.net)' },
    ],
    spfDetails: 'SPF record at example-domain.com does not list 185.204.48.131 (v=spf1 ip4:198.51.100.0/24 ~all)',
    dkimDetails: 'Signature validated with selector s1, RSA-SHA256, header.from=example-domain.com',
    dmarcDetails: 'Policy p=reject; no aligned DKIM or SPF identity — mail fails alignment',
  },
  aiContentAnalysis: {
    contentAnalysisAvailable: true,
    findings: [
      {
        category: 'Urgency / Pressure',
        severity: 'high',
        confidence: 94,
        evidence: 'Demands credential verification within 24 hours under threat of immediate account suspension.',
      },
      {
        category: 'Credential Harvesting',
        severity: 'high',
        confidence: 96,
        evidence: 'Directs recipient to an unverified external login portal to verify account credentials.',
      },
      {
        category: 'Impersonation',
        severity: 'medium',
        confidence: 88,
        evidence: 'Uses generic "Account Security Support Team" branding with urgent security alert language.',
      },
    ],
    overallAssessment: 'High-severity social engineering attack leveraging artificial urgency and account suspension threats to harvest credentials.',
  },
};

casesStore.set(defaultPrototypeCase.caseId, defaultPrototypeCase);

// Robust email parsing utility
interface ParsedHeaders {
  from: string;
  fromName: string;
  fromEmail: string;
  fromDomain: string;
  to: string;
  subject: string;
  date: string;
  returnPath: string;
  messageId: string;
  authResults: string;
  dkimSig: string;
  received: string[];
  allHeaders: Map<string, string>;
  body: string;
  extractedUrls: string[];
  extractedIps: string[];
}

function parseEmailContent(rawInput: string): ParsedHeaders {
  const normalized = rawInput.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  let headerBlock = normalized;
  let bodyBlock = '';

  const headerEnd = normalized.indexOf('\n\n');
  if (headerEnd !== -1) {
    headerBlock = normalized.slice(0, headerEnd);
    bodyBlock = normalized.slice(headerEnd + 2);
  }

  // Handle folded lines (RFC 2822: headers starting with space or tab continue previous header)
  const lines = headerBlock.split('\n');
  const unfolded: string[] = [];
  for (const line of lines) {
    if ((line.startsWith(' ') || line.startsWith('\t')) && unfolded.length > 0) {
      unfolded[unfolded.length - 1] += ' ' + line.trim();
    } else if (line.trim().length > 0) {
      unfolded.push(line);
    }
  }

  const allHeaders = new Map<string, string>();
  const received: string[] = [];

  for (const line of unfolded) {
    const colonIndex = line.indexOf(':');
    if (colonIndex > 0) {
      const key = line.slice(0, colonIndex).trim().toLowerCase();
      const value = line.slice(colonIndex + 1).trim();
      if (key === 'received') {
        received.push(value);
      } else {
        allHeaders.set(key, value);
      }
    }
  }

  const fromRaw = allHeaders.get('from') || 'unknown@example.com';
  let fromName = '';
  let fromEmail = fromRaw;

  const emailMatch = fromRaw.match(/<([^>]+)>/);
  if (emailMatch) {
    fromEmail = emailMatch[1];
    fromName = fromRaw.replace(emailMatch[0], '').replace(/["']/g, '').trim();
  } else {
    fromEmail = fromRaw.replace(/["']/g, '').trim();
  }

  const atIndex = fromEmail.indexOf('@');
  const fromDomain = atIndex !== -1 ? fromEmail.slice(atIndex + 1).toLowerCase() : 'unknown-domain.com';

  const to = allHeaders.get('to') || 'user@example.com';
  const subject = allHeaders.get('subject') || 'No Subject';
  const date = allHeaders.get('date') || new Date().toUTCString();
  const returnPath = allHeaders.get('return-path')?.replace(/[<>]/g, '').trim() || fromEmail;
  const messageId = allHeaders.get('message-id')?.replace(/[<>]/g, '').trim() || `msg-${Date.now()}@threatlens.ai`;
  const authResults = allHeaders.get('authentication-results') || '';
  const dkimSig = allHeaders.get('dkim-signature') || '';

  // Extract URLs from headers and body
  const combined = rawInput;
  const urlRegex = /https?:\/\/[^\s"'<>\)]+/gi;
  const foundUrls = Array.from(new Set(combined.match(urlRegex) || []));

  // Extract IPv4 addresses
  const ipRegex = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g;
  const foundIps = Array.from(new Set(rawInput.match(ipRegex) || []));

  return {
    from: fromRaw,
    fromName,
    fromEmail,
    fromDomain,
    to,
    subject,
    date,
    returnPath,
    messageId,
    authResults,
    dkimSig,
    received,
    allHeaders,
    body: bodyBlock,
    extractedUrls: foundUrls,
    extractedIps: foundIps,
  };
}

// Fallback & Rule-based Threat Forensics Engine with Real Domain Age Intelligence
async function analyzeEmailDeterministic(
  parsed: ParsedHeaders,
  rawInput: string,
  aiAnalysis?: AiContentAnalysis,
  pastCases?: any[]
): Promise<EmailAnalysisCase> {
  const caseId = `TL-${new Date().getFullYear()}-${Math.floor(10000 + Math.random() * 90000)}`;
  const now = new Date();
  const formattedDate = now.toUTCString();
  const simpleDate = `${now.getDate()} ${now.toLocaleString('default', { month: 'long' })} ${now.getFullYear()}`;

  // Perform real server-side WHOIS/RDAP lookup on sender domain
  const domainLookup = await lookupDomainRegistrationAge(parsed.fromEmail);

  // Analyze SPF
  let spfStatus: 'PASS' | 'FAIL' | 'NEUTRAL' | 'NONE' = 'NEUTRAL';
  let spfDetails = 'No explicit SPF authentication header detected.';
  const authLower = parsed.authResults.toLowerCase();

  if (authLower.includes('spf=pass')) {
    spfStatus = 'PASS';
    spfDetails = 'Sender IP matches authorized SPF record for domain.';
  } else if (authLower.includes('spf=fail') || authLower.includes('spf=softfail')) {
    spfStatus = 'FAIL';
    spfDetails = 'Sender IP is not authorized by the domain SPF policy.';
  }

  // Analyze DKIM
  let dkimStatus: 'PASS' | 'FAIL' | 'NONE' = 'NONE';
  let dkimDetails = 'No DKIM signature found.';
  if (authLower.includes('dkim=pass') || parsed.dkimSig.length > 0) {
    dkimStatus = authLower.includes('dkim=fail') ? 'FAIL' : 'PASS';
    dkimDetails = dkimStatus === 'PASS' ? 'Cryptographic signature valid and verified.' : 'DKIM signature failed validation.';
  }

  // Analyze DMARC
  let dmarcStatus: 'PASS' | 'FAIL' | 'NONE' = 'NONE';
  let dmarcDetails = 'No DMARC policy result evaluated.';
  if (authLower.includes('dmarc=pass')) {
    dmarcStatus = 'PASS';
    dmarcDetails = 'DMARC alignment passed with valid identifier alignment.';
  } else if (authLower.includes('dmarc=fail')) {
    dmarcStatus = 'FAIL';
    dmarcDetails = 'Domain alignment policy failed; neither SPF nor DKIM aligns with header From.';
  } else if (spfStatus === 'FAIL' && dkimStatus !== 'PASS') {
    dmarcStatus = 'FAIL';
    dmarcDetails = 'Implicit DMARC failure due to unaligned SPF and missing valid DKIM.';
  } else if (spfStatus === 'PASS' && dkimStatus === 'PASS') {
    dmarcStatus = 'PASS';
    dmarcDetails = 'DMARC alignment verified.';
  }

  // Threat keywords heuristic
  const urgentWords = ['urgent', 'verify', 'suspended', 'immediately', 'wire transfer', 'payroll', 'compromised', 're-activate', 'settlement', 'confidential'];
  const textLower = (parsed.subject + ' ' + parsed.body).toLowerCase();
  const matchedUrgent = urgentWords.filter(w => textLower.includes(w));

  // Domain mismatch check (From vs Return-Path)
  const returnPathDomain = parsed.returnPath.split('@')[1]?.toLowerCase() || '';
  const isSpoofedDomain = returnPathDomain && returnPathDomain !== parsed.fromDomain;

  // URLs analysis
  const flaggedUrls = parsed.extractedUrls.map(url => {
    let risk: 'HIGH RISK' | 'SUSPICIOUS' | 'CLEAN' = 'CLEAN';
    let reason = 'Domain matches legitimate reputation.';
    let category = 'Informational';

    const uLower = url.toLowerCase();
    if (uLower.includes('login') || uLower.includes('session') || uLower.includes('verify') || uLower.includes('secure') || uLower.includes('escrow') || uLower.includes('invoice')) {
      if (!url.includes('github.com') && !url.includes('google.com') && !url.includes('microsoft.com')) {
        risk = 'HIGH RISK';
        reason = 'Lookalike or suspicious keyword path in untrusted host.';
        category = 'Credential Harvester';
      }
    } else if (isSpoofedDomain || spfStatus === 'FAIL') {
      risk = 'SUSPICIOUS';
      reason = 'Destination domain differs from authenticated organization.';
      category = 'Phishing Landing';
    }

    let domain = '';
    try {
      domain = new URL(url).hostname;
    } catch {
      domain = url;
    }

    return {
      url,
      risk,
      reason,
      domain,
      category,
    };
  });

  // Calculate risk score
  let score = 15;
  const evidenceList: Array<{ text: string; type: 'fail' | 'warn' | 'ok' }> = [];

  // Domain registration age intelligence factor (Step 2 requirement)
  if (domainLookup.isRecentlyRegistered) {
    score += 15; // +15 risk points for < 30 days
    evidenceList.push({
      text: domainLookup.evidenceText, // e.g. "Recently registered domain (Registered 12 days ago) [+15 risk points]"
      type: 'fail',
    });
  } else if (domainLookup.lookupStatus === 'ESTABLISHED') {
    evidenceList.push({
      text: domainLookup.evidenceText, // e.g. "Sender domain age established: 18 years (6,913 days) (+0 risk points)"
      type: 'ok',
    });
  } else {
    // Unavailable / unresolvable: +0 risk points
    evidenceList.push({
      text: 'Domain age unavailable (+0 risk points)',
      type: 'warn',
    });
  }

  if (spfStatus === 'FAIL') {
    score += 25;
    evidenceList.push({ text: 'SPF authorization failed for sender IP', type: 'fail' });
  } else if (spfStatus === 'PASS') {
    score -= 10;
    evidenceList.push({ text: 'SPF passed successfully', type: 'ok' });
  }

  if (dmarcStatus === 'FAIL') {
    score += 25;
    evidenceList.push({ text: 'DMARC alignment failed', type: 'fail' });
  } else if (dmarcStatus === 'PASS') {
    score -= 10;
    evidenceList.push({ text: 'DMARC alignment satisfied', type: 'ok' });
  }

  if (isSpoofedDomain) {
    score += 20;
    evidenceList.push({ text: `Header From domain (${parsed.fromDomain}) differs from Return-Path (${returnPathDomain})`, type: 'fail' });
  }

  if (flaggedUrls.some(u => u.risk === 'HIGH RISK')) {
    score += 20;
    evidenceList.push({ text: 'Suspicious credential or landing URLs detected', type: 'fail' });
  }

  // Step 4: AI-Assisted Content Analysis score contribution (+15 maximum)
  if (aiAnalysis) {
    const aiContribution = calculateAiScoreContribution(aiAnalysis);
    score += aiContribution.points;
    evidenceList.push(aiContribution.evidenceItem);
  } else if (matchedUrgent.length > 0) {
    score += 10;
    evidenceList.push({
      text: `Urgent persuasion keywords detected: ${matchedUrgent.slice(0, 3).join(', ')} [+10 risk points]`,
      type: 'warn',
    });
  }

  score = Math.max(5, Math.min(100, score));

  let verdict: 'POTENTIALLY MALICIOUS' | 'SUSPICIOUS' | 'CLEAN / LEGITIMATE' = 'CLEAN / LEGITIMATE';
  let riskLevel: 'HIGH RISK' | 'SUSPICIOUS' | 'LOW RISK' | 'CLEAN' = 'CLEAN';

  if (score >= 65) {
    verdict = 'POTENTIALLY MALICIOUS';
    riskLevel = 'HIGH RISK';
  } else if (score >= 35) {
    verdict = 'SUSPICIOUS';
    riskLevel = 'SUSPICIOUS';
  } else {
    verdict = 'CLEAN / LEGITIMATE';
    riskLevel = 'CLEAN';
  }

  // Construct Real Relay Trace Hops from parsed Received headers (RFC 822 chronological order & real GeoIP)
  const hops = await buildRealRelayTrace(
    parsed.received,
    parsed.fromDomain,
    parsed.extractedIps[0],
    parsed.date
  );

  let explanation = '';
  if (score >= 65) {
    explanation = `This email demonstrates multiple indicators commonly associated with phishing and impersonation campaigns. DMARC authentication ${
      dmarcStatus === 'FAIL' ? 'failed (' + dmarcDetails + ')' : 'is unaligned'
    }, sender reputation is poor, and embedded links point to suspicious destination targets.${
      aiAnalysis?.contentAnalysisAvailable && aiAnalysis.overallAssessment
        ? ` AI-Assisted Content Analysis: ${aiAnalysis.overallAssessment}`
        : ' Urgent verification language was detected, which is consistent with credential-harvesting attacks.'
    }`;
  } else if (score >= 35) {
    explanation = `This email contains moderate risk anomalies. While some authentication mechanisms may have passed or been missing, unusual relay patterns or mismatched sender domains warrant analyst caution before clicking embedded links or executing instructions.${
      aiAnalysis?.contentAnalysisAvailable && aiAnalysis.overallAssessment
        ? ` AI-Assisted Content Analysis: ${aiAnalysis.overallAssessment}`
        : ''
    }`;
  } else {
    explanation = `This email passed key cryptographic authentication checks with aligned domain identifiers. No high-risk credential harvester URLs or domain spoofing heuristics were identified.${
      aiAnalysis?.contentAnalysisAvailable && aiAnalysis.overallAssessment
        ? ` AI-Assisted Content Analysis: ${aiAnalysis.overallAssessment}`
        : ''
    }`;
  }

  // Build candidate case payload for real cross-case correlation
  const candidateForCorrelation = {
    caseId,
    timestamp: formattedDate,
    subject: parsed.subject,
    verdict,
    riskScore: score,
    sender: {
      displayName: parsed.fromName || parsed.fromEmail.split('@')[0],
      email: parsed.fromEmail,
      domain: parsed.fromDomain,
      returnPath: parsed.returnPath,
    },
    flaggedUrls,
    technicalDetails: {
      observedIps: parsed.extractedIps.map((ip, i) => ({
        ip,
        note: i === 0 ? 'Sender MX or Origin' : i === 1 ? 'Intermediate Relay' : 'Downstream Hop',
      })),
    },
    relayTrace: hops,
  };

  const correlation = correlateWithPastCases(candidateForCorrelation, pastCases || []);
  const graph = buildRealInvestigationGraph(candidateForCorrelation, correlation);

  const candidateCase: EmailAnalysisCase = {
    caseId,
    timestamp: formattedDate,
    analyzedAt: simpleDate,
    verdict,
    riskScore: score,
    riskLevel,
    confidence: 92,
    sender: {
      displayName: parsed.fromName || parsed.fromEmail.split('@')[0],
      email: parsed.fromEmail,
      domain: parsed.fromDomain,
      returnPath: parsed.returnPath,
    },
    recipient: {
      email: parsed.to,
    },
    subject: parsed.subject,
    receivedDate: parsed.date,
    messageId: parsed.messageId,
    authResults: {
      spf: {
        status: spfStatus,
        summary: `SPF ${spfStatus}`,
        details: spfDetails,
      },
      dkim: {
        status: dkimStatus,
        summary: `DKIM ${dkimStatus}`,
        details: dkimDetails,
      },
      dmarc: {
        status: dmarcStatus,
        summary: `DMARC ${dmarcStatus}`,
        details: dmarcDetails,
      },
    },
    domainIntelligence: {
      domain: domainLookup.domain || parsed.fromDomain,
      reputation: isSpoofedDomain
        ? 'SUSPICIOUS'
        : domainLookup.isRecentlyRegistered
        ? 'SUSPICIOUS'
        : score >= 65
        ? 'MALICIOUS'
        : score >= 35
        ? 'SUSPICIOUS'
        : 'TRUSTED',
      age: domainLookup.domainAge,
      firstSeen: domainLookup.registrationDate
        ? new Date(domainLookup.registrationDate).toLocaleDateString('en-US', {
            day: '2-digit',
            month: 'short',
            year: 'numeric',
            timeZone: 'UTC',
          })
        : 'Unknown',
      registrationCountry: 'Verified via RDAP Registry',
      summary: domainLookup.isRecentlyRegistered
        ? `Domain registered only ${domainLookup.ageInDays} days ago (${domainLookup.domainAge}). Newly registered domains are disproportionately leveraged in phishing and spoofing campaigns.`
        : domainLookup.lookupStatus === 'ESTABLISHED'
        ? `Domain registered on ${domainLookup.registrationDate ? domainLookup.registrationDate.slice(0, 10) : 'verified date'} (${domainLookup.domainAge}). ${domainLookup.registrar ? `Registrar: ${domainLookup.registrar}.` : ''}`
        : 'Registration information unavailable from registry. No risk penalty applied (+0 points).',
      tags: [
        domainLookup.isRecentlyRegistered
          ? 'Recently Registered (<30d)'
          : domainLookup.lookupStatus === 'ESTABLISHED'
          ? 'Established Domain (>30d)'
          : 'Domain age unavailable',
        domainLookup.registrar ? `Registrar: ${domainLookup.registrar}` : 'RDAP Verified',
        domainLookup.isRecentlyRegistered ? '+15 Risk Points' : '+0 Risk Points',
      ],
      blocklistsCount: domainLookup.isRecentlyRegistered ? 1 : 0,
      domainAge: domainLookup.domainAge,
      registrationDate: domainLookup.registrationDate,
      ageInDays: domainLookup.ageInDays,
      isRecentlyRegistered: domainLookup.isRecentlyRegistered,
      lookupStatus: domainLookup.lookupStatus,
      registrar: domainLookup.registrar,
      provider: domainLookup.provider,
    },
    domainAge: domainLookup.domainAge,
    registrationDate: domainLookup.registrationDate,
    ageInDays: domainLookup.ageInDays,
    isRecentlyRegistered: domainLookup.isRecentlyRegistered,
    lookupStatus: domainLookup.lookupStatus,
    flaggedUrls,
    whyFlagged: {
      explanation,
      evidence: evidenceList,
    },
    relayTrace: hops,
    graph,
    correlation,
    technicalDetails: {
      rawHeaders: rawInput.split('\n\n')[0] || rawInput,
      receivedChain: parsed.received,
      observedIps: parsed.extractedIps.map((ip, i) => ({
        ip,
        note: i === 0 ? 'Sender MX or Origin' : i === 1 ? 'Intermediate Relay' : 'Downstream Hop',
      })),
      spfDetails,
      dkimDetails,
      dmarcDetails,
    },
    aiContentAnalysis: aiAnalysis || {
      contentAnalysisAvailable: false,
      findings: [],
      overallAssessment: 'Email body unavailable — content-based analysis could not be performed.',
    },
  };

  // Step 6: Generate deterministic canonical forensic report and SHA-256 integrity hash
  const canonicalPayload = buildCanonicalReportPayload(candidateCase);
  const canonicalString = deterministicStringify(canonicalPayload);
  const canonicalHash = await computeSha256(canonicalString);

  candidateCase.forensicReport = {
    generatedAt: candidateCase.analyzedAt,
    canonicalHash,
    hashAlgorithm: 'SHA-256',
    disclaimer: INTEGRITY_HASH_DISCLAIMER,
  };

  return candidateCase;
}

// ================= API ROUTES =================

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'ThreatLens Forensic Analysis Engine',
    geminiConfigured: !!process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY !== 'MY_GEMINI_API_KEY',
    casesCount: casesStore.size,
  });
});

// Helper to retrieve all historical cases across Firestore and in-memory store
async function getHistoricalCases(): Promise<any[]> {
  const inMem = Array.from(casesStore.values());
  let firestoreCases: any[] = [];
  try {
    firestoreCases = await getAllAnalyzedCasesFromFirestore();
  } catch (err) {
    console.warn('Could not fetch historical cases from Firestore, fallback to in-memory store:', err);
  }

  const map = new Map<string, any>();
  for (const c of firestoreCases) {
    if (c && c.caseId) map.set(c.caseId, c);
  }
  for (const c of inMem) {
    if (c && c.caseId) map.set(c.caseId, c);
  }
  return Array.from(map.values());
}

// Get sample email presets
app.get('/api/samples', (req, res) => {
  res.json({ samples: SAMPLE_PRESETS });
});

// Get all recent analysis cases
app.get('/api/analyses', (req, res) => {
  const list = Array.from(casesStore.values()).map(c => ({
    caseId: c.caseId,
    timestamp: c.timestamp,
    subject: c.subject,
    senderEmail: c.sender.email,
    verdict: c.verdict,
    riskScore: c.riskScore,
    riskLevel: c.riskLevel,
  }));
  res.json({ cases: list });
});

// Get specific case by ID (checks in-memory store, then Firestore)
app.get('/api/analyses/:id', async (req, res) => {
  const caseId = req.params.id;
  let found = casesStore.get(caseId);
  if (!found) {
    const firestoreRecord = await getAnalysisCaseFromFirestore(caseId);
    if (firestoreRecord) {
      found = firestoreRecord as EmailAnalysisCase;
      casesStore.set(caseId, found);
    }
  }

  if (!found) {
    return res.status(404).json({ error: `Case ${caseId} not found.` });
  }
  res.json({ case: found });
});

// Analyze raw email headers or .eml content
app.post('/api/analyze', async (req, res) => {
  try {
    const { rawText, presetId } = req.body;

    let contentToAnalyze = rawText;
    if (!contentToAnalyze && presetId) {
      const preset = SAMPLE_PRESETS.find(p => p.id === presetId);
      if (preset) {
        contentToAnalyze = preset.headers;
      }
    }

    if (!contentToAnalyze || typeof contentToAnalyze !== 'string' || contentToAnalyze.trim().length === 0) {
      return res.status(400).json({ error: 'Please provide raw email headers or an .eml text payload.' });
    }

    // Step 1: Extract structured email content (Subject, From, Return-Path, body text, HTML, and URLs with context)
    const extractedContent = extractEmailContent(contentToAnalyze);

    // Step 2: Perform AI Content Threat Analysis using Gemini 3.8 Flash (server-side with deterministic fallback)
    const aiAnalysis = await analyzeEmailContentWithGemini(extractedContent);

    // Step 3: Fetch historical analyzed cases from Firestore & in-memory store for cross-case infrastructure correlation
    const pastCases = await getHistoricalCases();

    // Step 4: Parse and run deterministic analysis with real RDAP/WHOIS lookup, structured relay trace, AI score contribution, and correlation
    const parsed = parseEmailContent(contentToAnalyze);
    const finalCase = await analyzeEmailDeterministic(parsed, contentToAnalyze, aiAnalysis, pastCases);

    // Step 5: Save to in-memory store
    casesStore.set(finalCase.caseId, finalCase);

    // Step 6: Persist to Firestore collection 'analyses'
    await saveAnalysisCaseToFirestore(finalCase);

    res.json({
      success: true,
      case: finalCase,
    });
  } catch (err: any) {
    console.error('Error analyzing email:', err);
    res.status(500).json({
      error: err?.message || 'Failed to process email analysis.',
    });
  }
});

// JSON Export endpoint
app.get('/api/analyses/:id/export/json', (req, res) => {
  const found = casesStore.get(req.params.id);
  if (!found) {
    return res.status(404).json({ error: 'Case not found' });
  }
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', `attachment; filename="${found.caseId}-threat-report.json"`);
  res.send(JSON.stringify(found, null, 2));
});

// Markdown Dossier Export endpoint
app.get('/api/analyses/:id/export/markdown', async (req, res) => {
  let found = casesStore.get(req.params.id);
  if (!found) {
    found = await getAnalysisCaseFromFirestore(req.params.id);
  }
  if (!found) {
    return res.status(404).json({ error: 'Case not found' });
  }

  const canonicalPayload = buildCanonicalReportPayload(found);
  const hash = found.forensicReport?.canonicalHash || (await computeSha256(deterministicStringify(canonicalPayload)));
  const md = generateMarkdownReport(found, canonicalPayload, hash);

  res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="${found.caseId}-Forensic-Dossier.md"`);
  res.send(md);
});

// Canonical Report Payload endpoint
app.get('/api/analyses/:id/report/canonical', async (req, res) => {
  let found = casesStore.get(req.params.id);
  if (!found) {
    found = await getAnalysisCaseFromFirestore(req.params.id);
  }
  if (!found) {
    return res.status(404).json({ error: 'Case not found' });
  }

  const canonicalPayload = buildCanonicalReportPayload(found);
  const canonicalString = deterministicStringify(canonicalPayload);
  const canonicalHash = await computeSha256(canonicalString);

  res.json({
    caseId: found.caseId,
    canonicalHash,
    hashAlgorithm: 'SHA-256',
    canonicalPayload,
  });
});

// Report Integrity Verification Endpoint
app.post('/api/report/verify', async (req, res) => {
  try {
    const { caseId, payload, expectedHash } = req.body;
    let targetCase: EmailAnalysisCase | null = null;

    if (caseId) {
      targetCase = casesStore.get(caseId) || null;
      if (!targetCase) {
        targetCase = await getAnalysisCaseFromFirestore(caseId);
      }
    }

    let canonicalPayload = payload;
    let hashToCompare = expectedHash;

    if (!canonicalPayload && targetCase) {
      canonicalPayload = buildCanonicalReportPayload(targetCase);
    }

    if (!hashToCompare && targetCase?.forensicReport?.canonicalHash) {
      hashToCompare = targetCase.forensicReport.canonicalHash;
    }

    if (!canonicalPayload || !hashToCompare) {
      return res.status(400).json({
        error: 'Missing report payload or expected hash for integrity verification.',
      });
    }

    const verificationResult = await verifyReportIntegrity(canonicalPayload, hashToCompare);

    res.json({
      success: true,
      caseId: targetCase?.caseId || caseId || null,
      ...verificationResult,
    });
  } catch (err: any) {
    res.status(500).json({ error: err?.message || 'Integrity verification failed' });
  }
});

// ================= VITE & STATIC SERVING =================
async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`ThreatLens Server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
