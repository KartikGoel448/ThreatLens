import React, { useState, useEffect, useMemo } from 'react';
import {
  FileText,
  Printer,
  Download,
  Copy,
  Plus,
  ShieldAlert,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Route,
  Network,
  Sparkles,
  ShieldCheck,
  Hash,
  RefreshCw,
  Eye,
  Check,
  AlertCircle,
  ExternalLink,
  Layers,
  Globe,
  Lock,
} from 'lucide-react';
import type { EmailAnalysisCase } from '../types';
import {
  buildCanonicalReportPayload,
  deterministicStringify,
  computeSha256,
  verifyReportIntegrity,
  generateMarkdownReport,
  generateClipboardSummary,
  INTEGRITY_HASH_DISCLAIMER,
  GEOLOCATION_DISCLAIMER,
  ATTRIBUTION_DISCLAIMER,
  AI_ANALYSIS_DISCLAIMER,
} from '../utils/forensicReport';

interface ReportViewProps {
  analysisCase: EmailAnalysisCase;
  onNavigate: (view: 'analyzer' | 'results' | 'trace' | 'graph' | 'report' | 'about') => void;
  onShowToast: (msg: string) => void;
}

export const ReportView: React.FC<ReportViewProps> = ({
  analysisCase,
  onNavigate,
  onShowToast,
}) => {
  const isHighRisk = analysisCase.riskScore >= 65;
  const isSuspicious = analysisCase.riskScore >= 35 && analysisCase.riskScore < 65;

  // Build canonical report payload strictly from actual case data
  const canonicalPayload = useMemo(
    () => buildCanonicalReportPayload(analysisCase),
    [analysisCase]
  );

  // State for integrity hash and verification
  const [reportHash, setReportHash] = useState<string>(
    analysisCase.forensicReport?.canonicalHash || ''
  );
  const [isVerifying, setIsVerifying] = useState(false);
  const [verificationResult, setVerificationResult] = useState<{
    verified: boolean;
    message: string;
    calculatedHash: string;
    timestamp?: string;
  } | null>(null);

  const [copiedHash, setCopiedHash] = useState(false);
  const [showCanonicalJson, setShowCanonicalJson] = useState(false);

  // Calculate canonical SHA-256 hash on mount or when case changes
  useEffect(() => {
    let isMounted = true;
    async function calculateHash() {
      const canonicalString = deterministicStringify(canonicalPayload);
      const hash = await computeSha256(canonicalString);
      if (isMounted) {
        setReportHash(hash);
      }
    }
    calculateHash();
    return () => {
      isMounted = false;
    };
  }, [canonicalPayload]);

  // SVG Gauge calculations for header chip (Radius = 62, Circumference = ~389.6)
  const radius = 62;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (analysisCase.riskScore / 100) * circumference;

  // Print Handler
  const handlePrint = () => {
    window.print();
  };

  // JSON Export Handler
  const handleExportJson = () => {
    const exportData = {
      caseId: analysisCase.caseId,
      exportedAt: new Date().toISOString(),
      reportIntegrityHash: {
        hashAlgorithm: 'SHA-256',
        canonicalHash: reportHash,
        disclaimer: INTEGRITY_HASH_DISCLAIMER,
      },
      forensicReportDossier: canonicalPayload,
      rawAnalysisCase: analysisCase,
    };

    const dataStr =
      'data:text/json;charset=utf-8,' +
      encodeURIComponent(JSON.stringify(exportData, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute(
      'download',
      `ThreatLens-${analysisCase.caseId}-Forensic-Report.json`
    );
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
    onShowToast(`Exported ${analysisCase.caseId}-Forensic-Report.json`);
  };

  // Markdown Dossier Export Handler
  const handleDownloadMarkdown = () => {
    const mdContent = generateMarkdownReport(analysisCase, canonicalPayload, reportHash);
    const dataStr = 'data:text/markdown;charset=utf-8,' + encodeURIComponent(mdContent);
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute(
      'download',
      `ThreatLens-${analysisCase.caseId}-Forensic-Dossier.md`
    );
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
    onShowToast(`Downloaded ${analysisCase.caseId}-Forensic-Dossier.md`);
  };

  // Copy Summary Handler
  const handleCopySummary = () => {
    const text = generateClipboardSummary(analysisCase, canonicalPayload, reportHash);
    navigator.clipboard.writeText(text);
    onShowToast('Copied forensic incident summary to clipboard.');
  };

  // Copy Hash Handler
  const handleCopyHash = () => {
    if (!reportHash) return;
    navigator.clipboard.writeText(reportHash);
    setCopiedHash(true);
    onShowToast('SHA-256 report hash copied to clipboard.');
    setTimeout(() => setCopiedHash(false), 2500);
  };

  // Live Integrity Verification Handler
  const handleVerifyIntegrity = async (simulateTamper = false) => {
    setIsVerifying(true);
    try {
      let payloadToVerify = canonicalPayload;
      if (simulateTamper) {
        // Create a temporary tampered copy to test tamper-detection
        payloadToVerify = JSON.parse(JSON.stringify(canonicalPayload));
        payloadToVerify.caseOverview.riskScore = 999;
      }

      const res = await verifyReportIntegrity(payloadToVerify, reportHash);
      setVerificationResult({
        verified: res.verified,
        message: res.message,
        calculatedHash: res.calculatedHash,
        timestamp: new Date().toLocaleTimeString(),
      });
      onShowToast(res.message);
    } catch (err: any) {
      setVerificationResult({
        verified: false,
        message: 'Integrity verification failed — error executing verification.',
        calculatedHash: 'Error',
      });
    } finally {
      setIsVerifying(false);
    }
  };

  return (
    <div className="w-full max-w-[1120px] mx-auto py-2">
      {/* Print-specific header (Visible only when printing) */}
      <div className="hidden print:block mb-6 pb-4 border-b-2 border-black text-black">
        <div className="flex justify-between items-start">
          <div>
            <h1 className="text-2xl font-black uppercase tracking-tight">ThreatLens SOC Forensic Dossier</h1>
            <p className="text-xs text-gray-700">Automated Forensic Email Threat Intelligence Platform</p>
          </div>
          <div className="text-right text-xs font-mono">
            <div><strong>CASE ID:</strong> {analysisCase.caseId}</div>
            <div><strong>ANALYZED:</strong> {analysisCase.analyzedAt}</div>
            <div><strong>VERDICT:</strong> {analysisCase.verdict} ({analysisCase.riskScore}/100)</div>
          </div>
        </div>
      </div>

      {/* Screen Hero Section */}
      <section className="text-center mb-8 no-print">
        <div className="text-xs font-mono font-bold text-[#3fd0f0] uppercase tracking-wider mb-2">
          Case Record · Generated {analysisCase.analyzedAt}
        </div>
        <h1 className="text-2xl md:text-4xl font-extrabold tracking-[-0.5px] text-[#f2f6fc]">
          Forensic Analysis Report
        </h1>
        <p className="text-sm md:text-base text-[#d8e2f0] mt-2 max-w-2xl mx-auto">
          Comprehensive forensic evidence dossier with cryptographic integrity verification, suitable for SOC incident response, compliance, or cross-team escalation.
        </p>
      </section>

      {/* ========================================================================= */}
      {/* REPORT INTEGRITY HASH (SHA-256) & VERIFICATION CARD (STEP 6 KEY FEATURE) */}
      {/* ========================================================================= */}
      <section className="bg-[#121c2d] border-2 border-[#203a5c] rounded-[16px] p-5 md:p-6 mb-8 shadow-[0_12px_36px_rgba(0,0,0,0.45)] relative overflow-hidden">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-5 pb-5 border-b border-[#202e45]">
          <div className="flex items-start gap-3.5">
            <div className="w-10 h-10 rounded-xl bg-[#0f283d] border border-[#23587d] flex items-center justify-center shrink-0 text-[#3fd0f0] shadow-[0_0_14px_rgba(63,208,240,0.2)]">
              <Hash className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-base md:text-lg font-extrabold text-[#f2f6fc] tracking-tight">
                  Report Integrity Hash (SHA-256)
                </h2>
                <span className="text-[11px] font-mono font-bold px-2 py-0.5 rounded-full bg-[#162e4a] text-[#7ce4fa] border border-[#23587d]">
                  Canonical JSON
                </span>
              </div>
              <p className="text-xs text-[#aab9d0] mt-1 max-w-2xl">
                Cryptographic digest computed from the deterministically sorted canonical forensic report dataset.
              </p>
            </div>
          </div>

          {/* Action Buttons for Integrity */}
          <div className="flex flex-wrap items-center gap-2.5 no-print">
            <button
              onClick={() => handleVerifyIntegrity(false)}
              disabled={isVerifying || !reportHash}
              className="inline-flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-bold bg-[#183452] border border-[#306896] text-[#7ce4fa] hover:bg-[#20456c] hover:border-[#3fd0f0] hover:text-white transition-all cursor-pointer shadow-sm disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isVerifying ? 'animate-spin' : ''}`} />
              Verify Report Integrity
            </button>

            <button
              onClick={() => handleVerifyIntegrity(true)}
              title="Simulate a tampered payload to verify mismatch detection"
              className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-semibold bg-[#211822] border border-[#522934] text-[#ff8a8e] hover:bg-[#341d27] transition-all cursor-pointer"
            >
              <AlertTriangle className="w-3.5 h-3.5" />
              Test Tamper Detection
            </button>

            <button
              onClick={() => setShowCanonicalJson(!showCanonicalJson)}
              className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-semibold bg-[#182339] border border-[#202e45] text-[#d8e2f0] hover:border-[#3fd0f0] transition-all cursor-pointer"
            >
              <Eye className="w-3.5 h-3.5" />
              {showCanonicalJson ? 'Hide Canonical Payload' : 'View Payload'}
            </button>
          </div>
        </div>

        {/* Display Hash Value */}
        <div className="mt-4 pt-1">
          <div className="text-[11px] font-mono font-bold text-[#aab9d0] uppercase tracking-wider mb-1.5 flex items-center justify-between">
            <span>Canonical SHA-256 Digest:</span>
            <span className="text-[10px] text-[#7ce4fa] font-sans lowercase">Deterministic key order (RFC-8785)</span>
          </div>
          <div className="flex items-center justify-between gap-3 p-3.5 rounded-xl bg-[#0b1320] border border-[#1d2f47] font-mono text-xs md:text-sm text-[#7ce4fa] break-all select-all">
            <span className="font-bold tracking-wide">{reportHash || 'Computing SHA-256...'}</span>
            <button
              onClick={handleCopyHash}
              className="p-1.5 rounded-lg bg-[#182339] hover:bg-[#233554] text-[#d8e2f0] hover:text-white transition-colors cursor-pointer shrink-0 no-print"
              title="Copy SHA-256 Hash"
            >
              {copiedHash ? <Check className="w-4 h-4 text-[#38d98c]" /> : <Copy className="w-4 h-4" />}
            </button>
          </div>
        </div>

        {/* Verification Status Banner */}
        {verificationResult && (
          <div
            className={`mt-4 p-4 rounded-xl border flex items-start gap-3 transition-all ${
              verificationResult.verified
                ? 'bg-[#10291e] border-[#267a52] text-[#4fe0a0]'
                : 'bg-[#301419] border-[#8f2f37] text-[#ff8a8e]'
            }`}
          >
            {verificationResult.verified ? (
              <CheckCircle2 className="w-5 h-5 text-[#38d98c] shrink-0 mt-0.5" />
            ) : (
              <XCircle className="w-5 h-5 text-[#ff5d63] shrink-0 mt-0.5" />
            )}
            <div className="text-xs md:text-sm">
              <div className="font-extrabold text-white mb-0.5 flex items-center gap-2">
                <span>{verificationResult.message}</span>
                {verificationResult.timestamp && (
                  <span className="text-[11px] font-mono font-normal text-[#aab9d0]">
                    · Checked at {verificationResult.timestamp}
                  </span>
                )}
              </div>
              <div className="font-mono text-[11px] opacity-90 break-all">
                Calculated Hash: {verificationResult.calculatedHash}
              </div>
            </div>
          </div>
        )}

        {/* Legal / Technical Disclaimer */}
        <div className="mt-4 pt-3 border-t border-[#1d2f47] flex items-start gap-2.5 text-[11px] text-[#8e9eb5] leading-relaxed">
          <ShieldCheck className="w-4 h-4 text-[#7ce4fa] shrink-0 mt-0.5" />
          <span>
            <strong className="text-[#d8e2f0]">Integrity Notice:</strong> {INTEGRITY_HASH_DISCLAIMER}
          </span>
        </div>

        {/* Collapsible Canonical Payload Drawer */}
        {showCanonicalJson && (
          <div className="mt-4 p-4 rounded-xl bg-[#090d15] border border-[#202e45] text-xs font-mono text-[#aab9d0] overflow-x-auto max-h-[300px]">
            <div className="flex justify-between items-center mb-2 pb-1 border-b border-[#1d2f47] text-[#7ce4fa] font-bold">
              <span>Canonical Report Payload (Deterministic Structure):</span>
              <button
                onClick={() => {
                  navigator.clipboard.writeText(deterministicStringify(canonicalPayload));
                  onShowToast('Copied canonical payload JSON to clipboard.');
                }}
                className="text-[11px] px-2 py-0.5 rounded bg-[#182339] text-[#f2f6fc] hover:bg-[#233554]"
              >
                Copy Raw JSON
              </button>
            </div>
            <pre className="text-[11px] leading-tight text-[#d8e2f0]">
              {JSON.stringify(canonicalPayload, null, 2)}
            </pre>
          </div>
        )}
      </section>

      {/* ========================================================================= */}
      {/* A. CASE OVERVIEW SECTION */}
      {/* ========================================================================= */}
      <div className="flex items-center justify-between mb-4">
        <h2 className="flex items-center gap-2.5 text-lg font-extrabold tracking-[0.2px] text-[#f2f6fc]">
          <span className="w-2.5 h-2.5 rounded-full bg-[#3fd0f0] shadow-[0_0_10px_#3fd0f0]"></span>
          A. Case Overview
        </h2>
        <span className="text-xs font-mono font-semibold text-[#aab9d0]">Section 1 of 8</span>
      </div>

      <section className="bg-[#121b2b] border border-[#202e45] rounded-[14px] p-6 mb-8 shadow-[0_12px_34px_rgba(0,0,0,0.38)]">
        <div className="flex flex-col md:flex-row items-center justify-between gap-8">
          {/* Gauge Score Chip */}
          <div className="relative w-[150px] h-[150px] shrink-0">
            <svg viewBox="0 0 150 150" className="w-full h-full">
              <defs>
                <linearGradient id="repGrad" x1="0" y1="0" x2="1" y2="1">
                  {isHighRisk ? (
                    <>
                      <stop offset="0%" stopColor="#ff8a8e" />
                      <stop offset="100%" stopColor="#e8454b" />
                    </>
                  ) : isSuspicious ? (
                    <>
                      <stop offset="0%" stopColor="#ffd269" />
                      <stop offset="100%" stopColor="#ffb92e" />
                    </>
                  ) : (
                    <>
                      <stop offset="0%" stopColor="#55f0a4" />
                      <stop offset="100%" stopColor="#38d98c" />
                    </>
                  )}
                </linearGradient>
              </defs>
              <circle
                cx="75"
                cy="75"
                r={radius}
                fill="none"
                stroke="#1c2939"
                strokeWidth="10"
              />
              <circle
                cx="75"
                cy="75"
                r={radius}
                fill="none"
                stroke="url(#repGrad)"
                strokeWidth="10"
                strokeLinecap="round"
                strokeDasharray={circumference}
                strokeDashoffset={strokeDashoffset}
                transform="rotate(-90 75 75)"
              />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center gap-0.5 pointer-events-none">
              <span className="text-[34px] font-extrabold leading-none text-[#f2f6fc]">
                {analysisCase.riskScore}
                <span className="text-base text-[#aab9d0]">/100</span>
              </span>
              <span
                className={`text-[11px] font-extrabold tracking-[1.4px] uppercase ${
                  isHighRisk
                    ? 'text-[#ff5d63]'
                    : isSuspicious
                    ? 'text-[#ffb92e]'
                    : 'text-[#38d98c]'
                }`}
              >
                {analysisCase.riskLevel}
              </span>
            </div>
          </div>

          {/* Metadata Grid */}
          <div className="w-full">
            <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 divide-y sm:divide-y-0 divide-[#202e45]">
              <div className="flex justify-between py-2 border-b border-[#202e45] text-sm">
                <dt className="text-[#aab9d0] font-semibold">ThreatLens Case ID</dt>
                <dd className="font-mono text-[#3fd0f0] font-bold">{analysisCase.caseId || 'Unavailable'}</dd>
              </div>
              <div className="flex justify-between py-2 border-b border-[#202e45] text-sm">
                <dt className="text-[#aab9d0] font-semibold">Risk Score</dt>
                <dd>
                  <span
                    className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold uppercase border ${
                      isHighRisk
                        ? 'text-[#ff7d82] bg-[#301419] border-[#8f2f37]'
                        : isSuspicious
                        ? 'text-[#ffc45c] bg-[#2c2110] border-[#8a641f]'
                        : 'text-[#4fe0a0] bg-[#122b20] border-[#267a52]'
                    }`}
                  >
                    {analysisCase.riskScore} / 100 — {analysisCase.riskLevel}
                  </span>
                </dd>
              </div>
              <div className="flex justify-between py-2 border-b border-[#202e45] text-sm">
                <dt className="text-[#aab9d0] font-semibold">Classification / Verdict</dt>
                <dd className="font-bold text-[#f2f6fc]">{analysisCase.verdict || 'Unavailable'}</dd>
              </div>
              <div className="flex justify-between py-2 border-b border-[#202e45] text-sm">
                <dt className="text-[#aab9d0] font-semibold">Analysis Timestamp</dt>
                <dd className="text-[#f2f6fc] font-semibold">{analysisCase.analyzedAt || 'Unavailable'}</dd>
              </div>
              <div className="flex justify-between py-2 border-b border-[#202e45] text-sm sm:col-span-2">
                <dt className="text-[#aab9d0] font-semibold">Analysis Confidence</dt>
                <dd className="font-mono text-xs font-bold text-[#7ce4fa]">
                  {typeof analysisCase.confidence === 'number' ? `${analysisCase.confidence}% Confidence Rating` : 'Unavailable'}
                </dd>
              </div>
              <div className="flex justify-between py-2 border-b border-[#202e45] text-sm sm:col-span-2">
                <dt className="text-[#aab9d0] font-semibold">Subject</dt>
                <dd className="text-[#f2f6fc] font-semibold truncate max-w-[450px]">
                  &quot;{analysisCase.subject || 'Unavailable'}&quot;
                </dd>
              </div>
              <div className="flex justify-between py-2 sm:col-span-2 text-sm">
                <dt className="text-[#aab9d0] font-semibold">Sender → Recipient</dt>
                <dd className="font-mono text-xs text-[#d8e2f0] truncate max-w-[450px]">
                  {analysisCase.sender?.email || 'Unavailable'} → {analysisCase.recipient?.email || 'Unavailable'}
                </dd>
              </div>
            </dl>
          </div>
        </div>

        {/* Executive Summary Narrative */}
        <div className="mt-6 pt-5 border-t border-[#202e45]">
          <div className="text-xs font-extrabold text-[#aab9d0] uppercase tracking-wider mb-2">
            Executive Threat Narrative
          </div>
          <p className="text-sm md:text-[15px] text-[#d8e2f0] leading-relaxed">
            {analysisCase.whyFlagged?.explanation || 'Unavailable'}
          </p>
        </div>
      </section>

      {/* ========================================================================= */}
      {/* B. SENDER & DOMAIN INTELLIGENCE SECTION */}
      {/* ========================================================================= */}
      <div className="flex items-center justify-between mb-4">
        <h2 className="flex items-center gap-2.5 text-lg font-extrabold tracking-[0.2px] text-[#f2f6fc]">
          <span className="w-2.5 h-2.5 rounded-full bg-[#3fd0f0] shadow-[0_0_10px_#3fd0f0]"></span>
          B. Sender & Domain Intelligence
        </h2>
        <span className="text-xs font-mono font-semibold text-[#aab9d0]">Section 2 of 8</span>
      </div>

      <section className="bg-[#121b2b] border border-[#202e45] rounded-[14px] p-6 mb-8">
        <dl className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-x-6 gap-y-4 text-sm">
          <div className="p-3 rounded-lg bg-[#182339] border border-[#202e45]">
            <dt className="text-xs text-[#aab9d0] font-semibold mb-1">From Header Address</dt>
            <dd className="font-mono text-xs text-[#f2f6fc] break-all font-bold">
              {analysisCase.sender?.email || 'Unavailable'}
            </dd>
            <div className="text-[11px] text-[#aab9d0] mt-0.5">
              Display Name: {analysisCase.sender?.displayName || 'Unavailable'}
            </div>
          </div>

          <div className="p-3 rounded-lg bg-[#182339] border border-[#202e45]">
            <dt className="text-xs text-[#aab9d0] font-semibold mb-1">Return-Path (Envelope Sender)</dt>
            <dd className="font-mono text-xs text-[#ffb92e] break-all font-bold">
              {analysisCase.sender?.returnPath || 'Unavailable'}
            </dd>
            <div className="text-[11px] text-[#aab9d0] mt-0.5">
              Return-Path Domain: {canonicalPayload.senderDomainIntelligence.returnPathDomain}
            </div>
          </div>

          <div className="p-3 rounded-lg bg-[#182339] border border-[#202e45]">
            <dt className="text-xs text-[#aab9d0] font-semibold mb-1">Domain Alignment Status</dt>
            <dd>
              <span
                className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-extrabold uppercase border ${
                  canonicalPayload.senderDomainIntelligence.domainAlignmentStatus === 'ALIGNED'
                    ? 'text-[#4fe0a0] bg-[#122b20] border-[#267a52]'
                    : canonicalPayload.senderDomainIntelligence.domainAlignmentStatus === 'MISALIGNED'
                    ? 'text-[#ff7d82] bg-[#301419] border-[#8f2f37]'
                    : 'text-[#aab9d0] bg-[#182339] border-[#2c3d59]'
                }`}
              >
                {canonicalPayload.senderDomainIntelligence.domainAlignmentStatus}
              </span>
            </dd>
            <div className="text-[11px] text-[#aab9d0] mt-1">
              {canonicalPayload.authenticationAnalysis.alignmentDiagnostics}
            </div>
          </div>

          <div className="p-3 rounded-lg bg-[#182339] border border-[#202e45]">
            <dt className="text-xs text-[#aab9d0] font-semibold mb-1">Registration Date (RDAP/WHOIS)</dt>
            <dd className="font-mono text-xs text-[#f2f6fc] font-bold">
              {analysisCase.domainIntelligence?.registrationDate
                ? new Date(analysisCase.domainIntelligence.registrationDate).toLocaleDateString('en-US', {
                    day: '2-digit',
                    month: 'short',
                    year: 'numeric',
                    timeZone: 'UTC',
                  })
                : 'Unavailable'}
            </dd>
            <div className="text-[11px] text-[#aab9d0] mt-0.5">
              Raw Record: {analysisCase.domainIntelligence?.registrationDate || 'Unavailable'}
            </div>
          </div>

          <div className="p-3 rounded-lg bg-[#182339] border border-[#202e45]">
            <dt className="text-xs text-[#aab9d0] font-semibold mb-1">Domain Registration Age</dt>
            <dd className="text-xs font-bold">
              {analysisCase.domainIntelligence?.isRecentlyRegistered ? (
                <span className="text-[#ff5d63]">
                  {analysisCase.domainIntelligence.domainAge || analysisCase.domainIntelligence.age || 'Unavailable'}
                </span>
              ) : analysisCase.domainIntelligence?.lookupStatus === 'ESTABLISHED' ? (
                <span className="text-[#38d98c]">
                  {analysisCase.domainIntelligence.domainAge || analysisCase.domainIntelligence.age || 'Unavailable'}
                </span>
              ) : (
                <span className="text-[#aab9d0] italic">Unavailable</span>
              )}
            </dd>
            <div className="text-[11px] text-[#aab9d0] mt-0.5">
              Status: {analysisCase.domainIntelligence?.isRecentlyRegistered ? 'Recently Registered (<30 days, +15 Risk)' : 'Established / Historical (+0)'}
            </div>
          </div>

          <div className="p-3 rounded-lg bg-[#182339] border border-[#202e45]">
            <dt className="text-xs text-[#aab9d0] font-semibold mb-1">Domain Registrar</dt>
            <dd className="font-mono text-xs text-[#d8e2f0] font-bold truncate">
              {analysisCase.domainIntelligence?.registrar || 'Unavailable'}
            </dd>
            <div className="text-[11px] text-[#aab9d0] mt-0.5">
              Domain Reputation: {analysisCase.domainIntelligence?.reputation || 'UNKNOWN'}
            </div>
          </div>
        </dl>
      </section>

      {/* ========================================================================= */}
      {/* C. AUTHENTICATION ANALYSIS SECTION */}
      {/* ========================================================================= */}
      <div className="flex items-center justify-between mb-4">
        <h2 className="flex items-center gap-2.5 text-lg font-extrabold tracking-[0.2px] text-[#f2f6fc]">
          <span className="w-2.5 h-2.5 rounded-full bg-[#3fd0f0] shadow-[0_0_10px_#3fd0f0]"></span>
          C. Authentication Analysis
        </h2>
        <span className="text-xs font-mono font-semibold text-[#aab9d0]">Section 3 of 8</span>
      </div>

      <section className="bg-[#121b2b] border border-[#202e45] rounded-[14px] p-6 mb-8">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
          {/* SPF */}
          <div className="p-4 rounded-xl bg-[#182339] border border-[#202e45]">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-bold text-[#aab9d0] uppercase tracking-wider">SPF Verification</span>
              <span
                className={`font-mono font-extrabold text-xs px-2 py-0.5 rounded border ${
                  analysisCase.authResults?.spf?.status === 'PASS'
                    ? 'text-[#4fe0a0] bg-[#122b20] border-[#267a52]'
                    : 'text-[#ff7d82] bg-[#301419] border-[#8f2f37]'
                }`}
              >
                {analysisCase.authResults?.spf?.status || 'Unavailable'}
              </span>
            </div>
            <p className="text-xs text-[#d8e2f0] leading-relaxed">
              {analysisCase.authResults?.spf?.details || analysisCase.authResults?.spf?.summary || 'Unavailable'}
            </p>
          </div>

          {/* DKIM */}
          <div className="p-4 rounded-xl bg-[#182339] border border-[#202e45]">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-bold text-[#aab9d0] uppercase tracking-wider">DKIM Signature</span>
              <span
                className={`font-mono font-extrabold text-xs px-2 py-0.5 rounded border ${
                  analysisCase.authResults?.dkim?.status === 'PASS'
                    ? 'text-[#4fe0a0] bg-[#122b20] border-[#267a52]'
                    : 'text-[#ff7d82] bg-[#301419] border-[#8f2f37]'
                }`}
              >
                {analysisCase.authResults?.dkim?.status || 'Unavailable'}
              </span>
            </div>
            <p className="text-xs text-[#d8e2f0] leading-relaxed">
              {analysisCase.authResults?.dkim?.details || analysisCase.authResults?.dkim?.summary || 'Unavailable'}
            </p>
          </div>

          {/* DMARC */}
          <div className="p-4 rounded-xl bg-[#182339] border border-[#202e45]">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-bold text-[#aab9d0] uppercase tracking-wider">DMARC Policy</span>
              <span
                className={`font-mono font-extrabold text-xs px-2 py-0.5 rounded border ${
                  analysisCase.authResults?.dmarc?.status === 'PASS'
                    ? 'text-[#4fe0a0] bg-[#122b20] border-[#267a52]'
                    : 'text-[#ff7d82] bg-[#301419] border-[#8f2f37]'
                }`}
              >
                {analysisCase.authResults?.dmarc?.status || 'Unavailable'}
              </span>
            </div>
            <p className="text-xs text-[#d8e2f0] leading-relaxed">
              {analysisCase.authResults?.dmarc?.details || analysisCase.authResults?.dmarc?.summary || 'Unavailable'}
            </p>
            <div className="text-[11px] font-mono text-[#ffb92e] mt-2">
              Enforced Policy: {analysisCase.authResults?.dmarc?.policy || 'Unavailable'}
            </div>
          </div>
        </div>
      </section>

      {/* ========================================================================= */}
      {/* D. RELAY TRACE SECTION */}
      {/* ========================================================================= */}
      <div className="flex items-center justify-between mb-4">
        <h2 className="flex items-center gap-2.5 text-lg font-extrabold tracking-[0.2px] text-[#f2f6fc]">
          <span className="w-2.5 h-2.5 rounded-full bg-[#3fd0f0] shadow-[0_0_10px_#3fd0f0]"></span>
          D. Relay Trace
        </h2>
        <span className="text-xs font-mono font-semibold text-[#aab9d0]">Section 4 of 8</span>
      </div>

      <section className="bg-[#121b2b] border border-[#202e45] rounded-[14px] p-6 mb-8">
        {/* Geolocation Disclaimer Notice */}
        <div className="flex items-start gap-3 p-3.5 rounded-xl bg-[#182339] border border-[#202e45] text-xs text-[#aab9d0] mb-5">
          <Globe className="w-4 h-4 text-[#3fd0f0] shrink-0 mt-0.5" />
          <span>
            <strong className="text-[#f2f6fc]">Network Geolocation Disclaimer:</strong> {GEOLOCATION_DISCLAIMER}
          </span>
        </div>

        <div className="space-y-3">
          {analysisCase.relayTrace && analysisCase.relayTrace.length > 0 ? (
            analysisCase.relayTrace.map((hop, idx) => (
              <div
                key={idx}
                className="p-4 rounded-xl bg-[#182339] border border-[#202e45] flex flex-col md:flex-row md:items-center justify-between gap-4 text-xs"
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="font-mono font-bold text-[#3fd0f0] px-2 py-0.5 rounded bg-[#0f1725] border border-[#202e45]">
                      Hop {hop.hopNumber}
                    </span>
                    <span className="font-extrabold text-[#f2f6fc]">{hop.host || 'Unavailable'}</span>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-extrabold uppercase border ${
                        hop.role === 'SOURCE'
                          ? 'text-[#8fe8ff] bg-[#0c2834] border-[#1d5c76]'
                          : hop.role === 'SUSPICIOUS'
                          ? 'text-[#ff7d82] bg-[#301419] border-[#8f2f37]'
                          : 'text-[#4fe0a0] bg-[#122b20] border-[#267a52]'
                      }`}
                    >
                      {hop.role}
                    </span>
                    {hop.ipType && (
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#0e1624] text-[#aab9d0] border border-[#202e45]">
                        {hop.ipType}
                      </span>
                    )}
                  </div>
                  <div className="font-mono text-[#aab9d0]">
                    IP Address: <span className="text-[#f2f6fc] font-bold">{hop.ip || 'Unavailable'}</span>
                    {hop.sendingHostname && hop.sendingHostname !== 'Unavailable' && ` · Sending Host: ${hop.sendingHostname}`}
                  </div>
                  <div className="text-[#aab9d0]">
                    Transit Delay: {hop.delayFromPreviousHop || 'Unavailable'} · Timezone: {hop.timezone || 'Unavailable'}
                  </div>
                </div>

                {/* Geolocation info */}
                <div className="text-left md:text-right font-mono text-[11px] text-[#d8e2f0] shrink-0">
                  <div className="text-[#3fd0f0] font-bold">
                    {hop.geolocation
                      ? `${hop.geolocation.city ? hop.geolocation.city + ', ' : ''}${hop.geolocation.country || 'Unavailable'}`
                      : 'Geolocation Unavailable'}
                  </div>
                  <div className="text-[#aab9d0]">
                    ISP/ASN: {hop.geolocation?.isp || 'Unavailable'} {hop.geolocation?.asn ? `(${hop.geolocation.asn})` : ''}
                  </div>
                </div>
              </div>
            ))
          ) : (
            <div className="text-xs text-[#aab9d0]">No relay hops recorded in message.</div>
          )}
        </div>
      </section>

      {/* ========================================================================= */}
      {/* E. URL INTELLIGENCE SECTION */}
      {/* ========================================================================= */}
      <div className="flex items-center justify-between mb-4">
        <h2 className="flex items-center gap-2.5 text-lg font-extrabold tracking-[0.2px] text-[#f2f6fc]">
          <span className="w-2.5 h-2.5 rounded-full bg-[#3fd0f0] shadow-[0_0_10px_#3fd0f0]"></span>
          E. URL Intelligence
        </h2>
        <span className="text-xs font-mono font-semibold text-[#aab9d0]">Section 5 of 8</span>
      </div>

      <section className="bg-[#121b2b] border border-[#202e45] rounded-[14px] p-6 mb-8">
        <div className="space-y-3">
          {analysisCase.flaggedUrls && analysisCase.flaggedUrls.length > 0 ? (
            analysisCase.flaggedUrls.map((u, i) => (
              <div key={i} className="p-3.5 rounded-xl bg-[#182339] border border-[#202e45] text-xs">
                <div className="flex items-center justify-between gap-2 mb-1.5">
                  <span className="font-mono text-[#7ce4fa] font-bold break-all">{u.url}</span>
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-extrabold uppercase shrink-0 border ${
                      u.risk === 'HIGH RISK'
                        ? 'bg-[#301419] text-[#ff5d63] border-[#8f2f37]'
                        : 'bg-[#2c2110] text-[#ffb92e] border-[#8a641f]'
                    }`}
                  >
                    {u.risk}
                  </span>
                </div>
                <div className="flex flex-wrap items-center gap-3 text-[#aab9d0]">
                  <span><strong>Host Domain:</strong> {u.domain}</span>
                  <span><strong>Security Finding:</strong> {u.reason}</span>
                </div>
              </div>
            ))
          ) : (
            <div className="p-4 rounded-xl border border-[#267a52]/40 bg-[#122b20]/40 text-xs md:text-sm text-[#4fe0a0] flex items-center gap-2.5">
              <CheckCircle2 className="w-4 h-4 text-[#38d98c] shrink-0" />
              <span>No suspicious or external credential-harvesting URLs extracted from email content.</span>
            </div>
          )}
        </div>
      </section>

      {/* ========================================================================= */}
      {/* F. AI-ASSISTED CONTENT ANALYSIS SECTION */}
      {/* ========================================================================= */}
      <div className="flex items-center justify-between mb-4">
        <h2 className="flex items-center gap-2.5 text-lg font-extrabold tracking-[0.2px] text-[#f2f6fc]">
          <span className="w-2.5 h-2.5 rounded-full bg-[#a78bfa] shadow-[0_0_10px_#a78bfa]"></span>
          F. AI-Assisted Content Analysis
          <span className="text-xs font-mono font-bold px-2 py-0.5 rounded-full bg-[#1e1b4b] border border-[#4338ca] text-[#c4b5fd]">
            Gemini 3.8 Flash
          </span>
        </h2>
        <span className="text-xs font-mono font-semibold text-[#aab9d0]">Section 6 of 8</span>
      </div>

      <section className="bg-[#121b2b] border border-[#202e45] rounded-[14px] p-6 mb-8">
        {/* Notice Disclaimer */}
        <div className="flex items-start gap-3 p-3.5 rounded-xl bg-[#182339] border border-[#202e45] text-xs text-[#aab9d0] mb-5">
          <Sparkles className="w-4 h-4 text-[#a78bfa] shrink-0 mt-0.5" />
          <span>
            <strong className="text-[#f2f6fc]">Probabilistic Interpretation Notice:</strong> {AI_ANALYSIS_DISCLAIMER}
          </span>
        </div>

        <div className="mb-5 pb-4 border-b border-[#202e45]">
          <div className="text-xs font-extrabold text-[#aab9d0] tracking-wider uppercase mb-1.5">
            Content Evaluation Assessment
          </div>
          <p className="text-sm md:text-base text-[#f2f6fc] leading-relaxed">
            {analysisCase.aiContentAnalysis?.overallAssessment ||
              (analysisCase.aiContentAnalysis?.contentAnalysisAvailable === false
                ? 'Email body unavailable — content-based analysis could not be performed.'
                : 'No significant phishing or social-engineering indicators were detected in the supplied email content.')}
          </p>
        </div>

        {/* Findings List */}
        {!analysisCase.aiContentAnalysis || !analysisCase.aiContentAnalysis.contentAnalysisAvailable ? (
          <div className="p-4 rounded-xl border border-[#202e45] bg-[#0e1624] text-xs md:text-sm text-[#aab9d0] flex items-center gap-2.5">
            <AlertTriangle className="w-4 h-4 text-[#ffb92e] shrink-0" />
            <span>Email body unavailable — content-based analysis could not be performed (+0 risk points).</span>
          </div>
        ) : analysisCase.aiContentAnalysis.findings.length === 0 ? (
          <div className="p-4 rounded-xl border border-[#267a52]/40 bg-[#122b20]/40 text-xs md:text-sm text-[#4fe0a0] flex items-center gap-2.5">
            <CheckCircle2 className="w-4 h-4 text-[#38d98c] shrink-0" />
            <span>No significant phishing or social-engineering indicators detected in message text (+0 risk points).</span>
          </div>
        ) : (
          <div className="space-y-3">
            <div className="text-xs font-extrabold text-[#aab9d0] tracking-wider uppercase">
              Identified Threat Categories ({analysisCase.aiContentAnalysis.findings.length})
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
              {analysisCase.aiContentAnalysis.findings.map((finding, idx) => (
                <div
                  key={idx}
                  className="p-4 rounded-xl border border-[#202e45] bg-[#182339] flex flex-col justify-between"
                >
                  <div className="flex items-center justify-between gap-2 mb-2">
                    <span className="font-extrabold text-sm text-[#f2f6fc]">
                      {finding.category}
                    </span>
                    <div className="flex items-center gap-1.5">
                      <span
                        className={`text-[10px] font-extrabold uppercase px-2 py-0.5 rounded border ${
                          finding.severity === 'high'
                            ? 'text-[#ff7d82] bg-[#301419] border-[#8f2f37]'
                            : finding.severity === 'medium'
                            ? 'text-[#ffc45c] bg-[#2c2110] border-[#8a641f]'
                            : 'text-[#8fe8ff] bg-[#0c2834] border-[#1d5c76]'
                        }`}
                      >
                        {finding.severity}
                      </span>
                      <span className="text-[10px] font-mono text-[#aab9d0] px-1.5 py-0.5 rounded bg-[#0f1725] border border-[#202e45]">
                        {finding.confidence}% conf
                      </span>
                    </div>
                  </div>
                  <p className="text-xs text-[#d8e2f0] leading-relaxed">
                    {finding.evidence}
                  </p>
                </div>
              ))}
            </div>
          </div>
        )}
      </section>

      {/* ========================================================================= */}
      {/* G. INVESTIGATION / CORRELATION SECTION */}
      {/* ========================================================================= */}
      <div className="flex items-center justify-between mb-4">
        <h2 className="flex items-center gap-2.5 text-lg font-extrabold tracking-[0.2px] text-[#f2f6fc]">
          <span className="w-2.5 h-2.5 rounded-full bg-[#3fd0f0] shadow-[0_0_10px_#3fd0f0]"></span>
          G. Investigation & Campaign Infrastructure Correlation
        </h2>
        <span className="text-xs font-mono font-semibold text-[#aab9d0]">Section 7 of 8</span>
      </div>

      <section className="bg-[#121b2b] border border-[#202e45] rounded-[14px] p-6 mb-8">
        {/* Attribution Disclaimer Notice */}
        <div className="flex items-start gap-3 p-3.5 rounded-xl bg-[#182339] border border-[#202e45] text-xs text-[#aab9d0] mb-5">
          <Network className="w-4 h-4 text-[#3fd0f0] shrink-0 mt-0.5" />
          <span>
            <strong className="text-[#f2f6fc]">Strict Attribution Disclaimer:</strong> {ATTRIBUTION_DISCLAIMER}
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-4">
          <div className="p-3.5 rounded-xl bg-[#182339] border border-[#202e45]">
            <div className="text-xs text-[#aab9d0] font-semibold mb-1">Campaign Status</div>
            <div className="text-sm font-extrabold text-[#f2f6fc]">
              {analysisCase.correlation?.campaignCandidate?.detected ? (
                <span className="text-[#ff7d82]">Candidate Detected</span>
              ) : (
                <span className="text-[#4fe0a0]">No Overlap Detected</span>
              )}
            </div>
          </div>

          <div className="p-3.5 rounded-xl bg-[#182339] border border-[#202e45]">
            <div className="text-xs text-[#aab9d0] font-semibold mb-1">Correlated Case Count</div>
            <div className="text-sm font-mono font-extrabold text-[#7ce4fa]">
              {analysisCase.correlation?.relatedCases?.length || 0} Linked Case(s)
            </div>
          </div>

          <div className="p-3.5 rounded-xl bg-[#182339] border border-[#202e45]">
            <div className="text-xs text-[#aab9d0] font-semibold mb-1">Shared Sender Domains</div>
            <div className="text-sm font-mono font-bold text-[#ffb92e]">
              {canonicalPayload.investigationCorrelation.sharedDomains.length > 0
                ? canonicalPayload.investigationCorrelation.sharedDomains.join(', ')
                : 'None'}
            </div>
          </div>

          <div className="p-3.5 rounded-xl bg-[#182339] border border-[#202e45]">
            <div className="text-xs text-[#aab9d0] font-semibold mb-1">Shared Relay IPs</div>
            <div className="text-sm font-mono font-bold text-[#ff8a8e]">
              {canonicalPayload.investigationCorrelation.sharedIps.length > 0
                ? canonicalPayload.investigationCorrelation.sharedIps.join(', ')
                : 'None'}
            </div>
          </div>
        </div>
      </section>

      {/* ========================================================================= */}
      {/* H. KEY EVIDENCE SUMMARY */}
      {/* ========================================================================= */}
      <div className="flex items-center justify-between mb-4">
        <h2 className="flex items-center gap-2.5 text-lg font-extrabold tracking-[0.2px] text-[#f2f6fc]">
          <span className="w-2.5 h-2.5 rounded-full bg-[#3fd0f0] shadow-[0_0_10px_#3fd0f0]"></span>
          H. Key Evidence Findings
        </h2>
        <span className="text-xs font-mono font-semibold text-[#aab9d0]">Section 8 of 8</span>
      </div>

      <section className="bg-[#121b2b] border border-[#202e45] rounded-[14px] p-6 mb-8">
        <div className="space-y-2.5">
          {canonicalPayload.keyEvidence && canonicalPayload.keyEvidence.length > 0 ? (
            canonicalPayload.keyEvidence.map((ev, idx) => (
              <div
                key={idx}
                className="p-3.5 rounded-xl bg-[#182339] border border-[#202e45] flex items-start gap-3 text-xs"
              >
                <div className="shrink-0 mt-0.5">
                  {ev.type === 'fail' ? (
                    <XCircle className="w-4 h-4 text-[#ff5d63]" />
                  ) : ev.type === 'warn' ? (
                    <AlertTriangle className="w-4 h-4 text-[#ffb92e]" />
                  ) : (
                    <CheckCircle2 className="w-4 h-4 text-[#38d98c]" />
                  )}
                </div>
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="font-mono text-[10px] font-extrabold uppercase px-2 py-0.5 rounded bg-[#0f1725] text-[#7ce4fa] border border-[#202e45]">
                      {ev.source}
                    </span>
                  </div>
                  <p className="text-[#d8e2f0] leading-relaxed">{ev.evidence}</p>
                </div>
              </div>
            ))
          ) : (
            <div className="text-xs text-[#aab9d0]">No evidence items recorded.</div>
          )}
        </div>
      </section>

      {/* ========================================================================= */}
      {/* EXPORT & ACTION CONTROLS */}
      {/* ========================================================================= */}
      <section className="flex flex-wrap items-center justify-center gap-3 p-7 rounded-[16px] border border-dashed border-[#31445f] bg-[#121c2d] no-print">
        <button
          onClick={handlePrint}
          className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-bold bg-[#182339] border border-[#31445f] text-[#d8e2f0] hover:border-[#3fd0f0] hover:text-[#3fd0f0] transition-colors cursor-pointer shadow-sm"
        >
          <Printer className="w-4 h-4" />
          Export PDF / Print
        </button>

        <button
          onClick={handleExportJson}
          className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-bold bg-[#182339] border border-[#31445f] text-[#d8e2f0] hover:border-[#3fd0f0] hover:text-[#3fd0f0] transition-colors cursor-pointer shadow-sm"
        >
          <Download className="w-4 h-4" />
          Export JSON
        </button>

        <button
          onClick={handleDownloadMarkdown}
          className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-bold bg-[#182339] border border-[#31445f] text-[#d8e2f0] hover:border-[#3fd0f0] hover:text-[#3fd0f0] transition-colors cursor-pointer shadow-sm"
        >
          <FileText className="w-4 h-4" />
          Download Markdown Dossier
        </button>

        <button
          onClick={handleCopySummary}
          className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-bold bg-[#182339] border border-[#31445f] text-[#d8e2f0] hover:border-[#3fd0f0] hover:text-[#3fd0f0] transition-colors cursor-pointer shadow-sm"
        >
          <Copy className="w-4 h-4" />
          Copy Summary
        </button>

        <button
          onClick={() => onNavigate('analyzer')}
          className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-bold bg-gradient-to-b from-[#ff6a6f] to-[#e8454b] text-white shadow-[0_4px_18px_rgba(232,69,75,0.3)] hover:brightness-110 transition-colors cursor-pointer"
        >
          <Plus className="w-4 h-4 stroke-[2.2]" />
          Start New Analysis
        </button>
      </section>
    </div>
  );
};
