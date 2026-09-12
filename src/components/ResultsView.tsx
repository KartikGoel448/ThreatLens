import React, { useState } from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  ExternalLink,
  ChevronDown,
  CheckCircle2,
  XCircle,
  Copy,
  Share2,
  FileText,
  Route,
  Network,
  Globe,
  Lock,
  Sparkles,
  Info,
} from 'lucide-react';
import type { EmailAnalysisCase } from '../types';

interface ResultsViewProps {
  analysisCase: EmailAnalysisCase;
  onNavigate: (view: 'analyzer' | 'results' | 'trace' | 'graph' | 'report' | 'about') => void;
  onShowToast: (msg: string) => void;
}

export const ResultsView: React.FC<ResultsViewProps> = ({
  analysisCase,
  onNavigate,
  onShowToast,
}) => {
  const [copiedUrl, setCopiedUrl] = useState<string | null>(null);

  // SVG Gauge calculation
  // Radius = 86, Circumference = 2 * PI * 86 = ~540.4
  const radius = 86;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (analysisCase.riskScore / 100) * circumference;

  const isHighRisk = analysisCase.riskScore >= 65;
  const isSuspicious = analysisCase.riskScore >= 35 && analysisCase.riskScore < 65;
  const isClean = analysisCase.riskScore < 35;

  const handleCopyUrl = (url: string) => {
    navigator.clipboard.writeText(url);
    setCopiedUrl(url);
    onShowToast(`Copied indicator URL: ${url.slice(0, 40)}...`);
    setTimeout(() => setCopiedUrl(null), 2500);
  };

  return (
    <div className="w-full max-w-[1240px] mx-auto py-2">
      {/* Risk Overview Grid */}
      <section className="grid grid-cols-1 lg:grid-cols-[340px_1fr] gap-6 items-stretch mb-6">
        {/* Risk Gauge Card */}
        <div className="bg-[#121b2b] border border-[#202e45] rounded-[14px] p-6 shadow-[0_12px_34px_rgba(0,0,0,0.38)] flex flex-col justify-center items-center">
          <div className="relative w-[258px] h-[258px] mx-auto">
            <svg
              className={`w-full h-full ${
                isHighRisk
                  ? 'drop-shadow-[0_0_16px_rgba(255,93,99,0.45)]'
                  : isSuspicious
                  ? 'drop-shadow-[0_0_16px_rgba(255,185,46,0.45)]'
                  : 'drop-shadow-[0_0_16px_rgba(56,217,140,0.45)]'
              }`}
              viewBox="0 0 220 220"
            >
              <defs>
                <linearGradient id="gaugeGrad" x1="0" y1="0" x2="1" y2="1">
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
              {/* Background Ring */}
              <circle
                cx="110"
                cy="110"
                r={radius}
                fill="none"
                stroke="#1c2939"
                strokeWidth="13"
              />
              {/* Filled Ring */}
              <circle
                cx="110"
                cy="110"
                r={radius}
                fill="none"
                stroke="url(#gaugeGrad)"
                strokeWidth="13"
                strokeLinecap="round"
                strokeDasharray={circumference}
                strokeDashoffset={strokeDashoffset}
                transform="rotate(-90 110 110)"
                className="transition-all duration-1000 ease-out"
              />
              <text
                x="20"
                y="196"
                fill="#5b6f8c"
                fontSize="12"
                fontFamily="SF Mono,Consolas,monospace"
              >
                0
              </text>
              <text
                x="184"
                y="196"
                fill="#5b6f8c"
                fontSize="12"
                fontFamily="SF Mono,Consolas,monospace"
              >
                100
              </text>
            </svg>

            <div className="absolute inset-0 flex flex-col items-center justify-center gap-0.5 pointer-events-none">
              <span className="text-[46px] font-extrabold tracking-[-1px] leading-none text-[#f2f6fc]">
                {analysisCase.riskScore}
                <span className="text-[22px] text-[#aab9d0]">/100</span>
              </span>
              <span
                className={`text-[13px] font-extrabold tracking-[1.6px] uppercase ${
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

          <div className="text-center mt-3">
            <span
              className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-extrabold uppercase tracking-wide border ${
                isHighRisk
                  ? 'text-[#ff7d82] bg-[#301419] border-[#8f2f37]'
                  : isSuspicious
                  ? 'text-[#ffc45c] bg-[#2c2110] border-[#8a641f]'
                  : 'text-[#4fe0a0] bg-[#122b20] border-[#267a52]'
              }`}
            >
              <span className="w-1.5 h-1.5 rounded-full bg-current"></span>
              {analysisCase.verdict}
            </span>
          </div>
        </div>

        {/* Analysis Verdict Card */}
        <div className="bg-[#121b2b] border border-[#202e45] rounded-[14px] p-6 shadow-[0_12px_34px_rgba(0,0,0,0.38)] flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2.5 text-base font-extrabold text-[#f2f6fc] mb-4">
              <span
                className={`w-2.5 h-2.5 rounded-full ${
                  isHighRisk
                    ? 'bg-[#ff5d63] shadow-[0_0_10px_#ff5d63]'
                    : isSuspicious
                    ? 'bg-[#ffb92e] shadow-[0_0_10px_#ffb92e]'
                    : 'bg-[#38d98c] shadow-[0_0_10px_#38d98c]'
                }`}
              ></span>
              Analysis Verdict
            </div>

            <dl className="divide-y divide-[#202e45]">
              <div className="flex justify-between items-center py-2.5 text-sm">
                <dt className="text-[#aab9d0] font-semibold">Verdict</dt>
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
                    {analysisCase.verdict}
                  </span>
                </dd>
              </div>

              <div className="flex justify-between items-center py-2.5 text-sm">
                <dt className="text-[#aab9d0] font-semibold">Sender</dt>
                <dd className="font-mono text-[#f2f6fc] text-xs md:text-sm truncate max-w-[320px]">
                  {analysisCase.sender.email}
                </dd>
              </div>

              <div className="flex justify-between items-center py-2.5 text-sm">
                <dt className="text-[#aab9d0] font-semibold">Recipient</dt>
                <dd className="font-mono text-[#f2f6fc] text-xs md:text-sm truncate max-w-[320px]">
                  {analysisCase.recipient.email}
                </dd>
              </div>

              <div className="flex justify-between items-center py-2.5 text-sm">
                <dt className="text-[#aab9d0] font-semibold">Subject</dt>
                <dd className="text-[#f2f6fc] font-semibold truncate max-w-[320px]">
                  &quot;{analysisCase.subject}&quot;
                </dd>
              </div>

              <div className="flex justify-between items-center py-2.5 text-sm">
                <dt className="text-[#aab9d0] font-semibold">Received</dt>
                <dd className="font-mono text-[#f2f6fc] text-xs md:text-sm">
                  {analysisCase.receivedDate}
                </dd>
              </div>

              <div className="flex justify-between items-center py-2.5 text-sm">
                <dt className="text-[#aab9d0] font-semibold">Case ID</dt>
                <dd className="font-mono text-[#3fd0f0] font-bold text-xs md:text-sm">
                  {analysisCase.caseId}
                </dd>
              </div>
            </dl>
          </div>

          <div className="mt-4 p-3.5 border border-[#202e45] rounded-xl bg-[#182339]">
            <div className="flex justify-between items-center mb-1.5">
              <span className="font-extrabold text-[13.5px] text-[#f2f6fc]">
                Analysis Confidence
              </span>
              <span className="font-mono font-extrabold text-[#3fd0f0] text-sm">
                {analysisCase.confidence}%
              </span>
            </div>
            <div className="h-2 rounded-full bg-[#1a2740] overflow-hidden">
              <div
                className="h-full rounded-full bg-gradient-to-r from-[#17a7d8] to-[#3fd0f0] transition-all duration-800"
                style={{ width: `${analysisCase.confidence}%` }}
              ></div>
            </div>
          </div>
        </div>
      </section>

      {/* Investigation Actions Toolbar */}
      <section className="flex flex-wrap gap-2.5 mb-8">
        <button
          onClick={() => onNavigate('trace')}
          className="inline-flex items-center gap-2 rounded-xl text-sm font-bold px-4 py-2.5 bg-transparent border border-[#31445f] text-[#d8e2f0] hover:border-[#3fd0f0] hover:text-[#3fd0f0] transition-all cursor-pointer"
        >
          <Route className="w-4 h-4" />
          Relay Trace
        </button>
        <button
          onClick={() => onNavigate('graph')}
          className="inline-flex items-center gap-2 rounded-xl text-sm font-bold px-4 py-2.5 bg-transparent border border-[#31445f] text-[#d8e2f0] hover:border-[#3fd0f0] hover:text-[#3fd0f0] transition-all cursor-pointer"
        >
          <Network className="w-4 h-4" />
          Investigation Graph
        </button>
        <button
          onClick={() => onNavigate('report')}
          className="inline-flex items-center gap-2 rounded-xl text-sm font-bold px-4 py-2.5 bg-gradient-to-b from-[#2ec9ec] to-[#17a7d8] text-[#06131c] shadow-[0_4px_18px_rgba(23,167,216,0.35)] hover:brightness-110 transition-all cursor-pointer"
        >
          <FileText className="w-4 h-4 stroke-[2.2]" />
          Forensic Report
        </button>
      </section>

      {/* Authentication Results 3-Cards */}
      <h2 className="flex items-center gap-2.5 text-lg font-extrabold tracking-[0.2px] mb-4 text-[#f2f6fc]">
        <span className="w-2 h-2 rounded-full bg-[#3fd0f0] shadow-[0_0_10px_#3fd0f0]"></span>
        Authentication Results
      </h2>

      <section className="grid grid-cols-1 md:grid-cols-3 gap-5 mb-8">
        {/* SPF */}
        <div
          className={`rounded-[14px] p-5 border transition-all ${
            analysisCase.authResults.spf.status === 'PASS'
              ? 'border-[#267a52] bg-gradient-to-b from-[#122b20] to-[#121b2b]'
              : 'border-[#8f2f37] bg-gradient-to-b from-[#301419] to-[#121b2b]'
          }`}
        >
          <div className="flex items-center justify-between mb-2">
            <span
              className={`font-mono font-extrabold text-base tracking-wider ${
                analysisCase.authResults.spf.status === 'PASS' ? 'text-[#38d98c]' : 'text-[#ff5d63]'
              }`}
            >
              SPF
            </span>
            <span
              className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-extrabold uppercase border ${
                analysisCase.authResults.spf.status === 'PASS'
                  ? 'text-[#4fe0a0] bg-[#122b20] border-[#267a52]'
                  : 'text-[#ff7d82] bg-[#301419] border-[#8f2f37]'
              }`}
            >
              {analysisCase.authResults.spf.status}
            </span>
          </div>
          <p className="text-sm text-[#d8e2f0] leading-relaxed">
            {analysisCase.authResults.spf.details}
          </p>
        </div>

        {/* DKIM */}
        <div
          className={`rounded-[14px] p-5 border transition-all ${
            analysisCase.authResults.dkim.status === 'PASS'
              ? 'border-[#267a52] bg-gradient-to-b from-[#122b20] to-[#121b2b]'
              : 'border-[#8f2f37] bg-gradient-to-b from-[#301419] to-[#121b2b]'
          }`}
        >
          <div className="flex items-center justify-between mb-2">
            <span
              className={`font-mono font-extrabold text-base tracking-wider ${
                analysisCase.authResults.dkim.status === 'PASS' ? 'text-[#38d98c]' : 'text-[#ff5d63]'
              }`}
            >
              DKIM
            </span>
            <span
              className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-extrabold uppercase border ${
                analysisCase.authResults.dkim.status === 'PASS'
                  ? 'text-[#4fe0a0] bg-[#122b20] border-[#267a52]'
                  : 'text-[#ff7d82] bg-[#301419] border-[#8f2f37]'
              }`}
            >
              {analysisCase.authResults.dkim.status}
            </span>
          </div>
          <p className="text-sm text-[#d8e2f0] leading-relaxed">
            {analysisCase.authResults.dkim.details}
          </p>
        </div>

        {/* DMARC */}
        <div
          className={`rounded-[14px] p-5 border transition-all ${
            analysisCase.authResults.dmarc.status === 'PASS'
              ? 'border-[#267a52] bg-gradient-to-b from-[#122b20] to-[#121b2b]'
              : 'border-[#8f2f37] bg-gradient-to-b from-[#301419] to-[#121b2b]'
          }`}
        >
          <div className="flex items-center justify-between mb-2">
            <span
              className={`font-mono font-extrabold text-base tracking-wider ${
                analysisCase.authResults.dmarc.status === 'PASS' ? 'text-[#38d98c]' : 'text-[#ff5d63]'
              }`}
            >
              DMARC
            </span>
            <span
              className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-extrabold uppercase border ${
                analysisCase.authResults.dmarc.status === 'PASS'
                  ? 'text-[#4fe0a0] bg-[#122b20] border-[#267a52]'
                  : 'text-[#ff7d82] bg-[#301419] border-[#8f2f37]'
              }`}
            >
              {analysisCase.authResults.dmarc.status}
            </span>
          </div>
          <p className="text-sm text-[#d8e2f0] leading-relaxed">
            {analysisCase.authResults.dmarc.details}
          </p>
        </div>
      </section>

      {/* Sender Domain Intelligence */}
      <h2 className="flex items-center gap-2.5 text-lg font-extrabold tracking-[0.2px] mb-4 text-[#f2f6fc]">
        <span className="w-2 h-2 rounded-full bg-[#3fd0f0] shadow-[0_0_10px_#3fd0f0]"></span>
        Sender Domain Intelligence
      </h2>

      <section className="bg-[#121b2b] border border-[#202e45] rounded-[14px] p-6 mb-8 shadow-[0_4px_20px_rgba(0,0,0,0.25)]">
        <div className="grid grid-cols-1 md:grid-cols-[1.2fr_1fr] gap-6 items-start">
          <dl className="divide-y divide-[#202e45]">
            <div className="flex justify-between items-center py-2.5 text-sm">
              <dt className="text-[#aab9d0] font-semibold">Domain</dt>
              <dd className="font-mono text-[#ffb92e] font-bold">
                {analysisCase.domainIntelligence.domain}
              </dd>
            </div>
            <div className="flex justify-between items-center py-2.5 text-sm">
              <dt className="text-[#aab9d0] font-semibold">Registration Date</dt>
              <dd className="font-mono text-sm text-[#f2f6fc] font-semibold">
                {analysisCase.domainIntelligence.registrationDate
                  ? new Date(analysisCase.domainIntelligence.registrationDate).toLocaleDateString('en-US', {
                      day: '2-digit',
                      month: 'short',
                      year: 'numeric',
                      timeZone: 'UTC',
                    })
                  : 'Unavailable'}
              </dd>
            </div>
            <div className="flex justify-between items-center py-2.5 text-sm">
              <dt className="text-[#aab9d0] font-semibold">Domain Age</dt>
              <dd className="font-semibold">
                {analysisCase.domainIntelligence.isRecentlyRegistered ? (
                  <span className="text-[#ff5d63] font-bold flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-[#ff5d63] animate-ping"></span>
                    {analysisCase.domainIntelligence.domainAge || analysisCase.domainIntelligence.age}
                  </span>
                ) : analysisCase.domainIntelligence.lookupStatus === 'ESTABLISHED' ? (
                  <span className="text-[#38d98c]">
                    {analysisCase.domainIntelligence.domainAge || analysisCase.domainIntelligence.age}
                  </span>
                ) : (
                  <span className="text-[#aab9d0] italic">Domain age unavailable</span>
                )}
              </dd>
            </div>
            <div className="flex justify-between items-center py-2.5 text-sm">
              <dt className="text-[#aab9d0] font-semibold">Status</dt>
              <dd>
                {analysisCase.domainIntelligence.isRecentlyRegistered ? (
                  <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-extrabold uppercase border text-[#ff7d82] bg-[#301419] border-[#8f2f37]">
                    <span className="w-1.5 h-1.5 rounded-full bg-[#ff7d82]"></span>
                    Recently Registered Domain (+15)
                  </span>
                ) : analysisCase.domainIntelligence.lookupStatus === 'ESTABLISHED' ? (
                  <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-bold uppercase border text-[#4fe0a0] bg-[#122b20] border-[#267a52]">
                    <span className="w-1.5 h-1.5 rounded-full bg-[#4fe0a0]"></span>
                    Established Domain (+0)
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium uppercase border text-[#aab9d0] bg-[#182339] border-[#2c3d59]">
                    Domain age unavailable (+0)
                  </span>
                )}
              </dd>
            </div>
            {analysisCase.domainIntelligence.registrar && (
              <div className="flex justify-between items-center py-2.5 text-sm">
                <dt className="text-[#aab9d0] font-semibold">Registrar</dt>
                <dd className="text-xs text-[#d8e2f0] font-mono">
                  {analysisCase.domainIntelligence.registrar}
                </dd>
              </div>
            )}
            <div className="flex justify-between items-center py-2.5 text-sm">
              <dt className="text-[#aab9d0] font-semibold">Reputation</dt>
              <dd>
                <span
                  className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold uppercase border ${
                    analysisCase.domainIntelligence.reputation === 'MALICIOUS'
                      ? 'text-[#ff7d82] bg-[#301419] border-[#8f2f37]'
                      : analysisCase.domainIntelligence.reputation === 'SUSPICIOUS'
                      ? 'text-[#ffc45c] bg-[#2c2110] border-[#8a641f]'
                      : 'text-[#4fe0a0] bg-[#122b20] border-[#267a52]'
                  }`}
                >
                  {analysisCase.domainIntelligence.reputation}
                </span>
              </dd>
            </div>
          </dl>

          <div>
            <div className="font-extrabold text-xs text-[#aab9d0] tracking-wider uppercase mb-2">
              Reputation & Forensic Summary
            </div>
            <p className="text-sm text-[#d8e2f0] leading-relaxed">
              {analysisCase.domainIntelligence.summary}
            </p>
            <div className="flex gap-2 flex-wrap mt-3.5">
              {analysisCase.domainIntelligence.tags.map((tag, i) => (
                <span
                  key={i}
                  className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-bold border ${
                    tag.includes('Recently Registered') || tag.includes('+15')
                      ? 'text-[#ff7d82] bg-[#301419] border-[#8f2f37]'
                      : 'text-[#ffc45c] bg-[#2c2110] border-[#8a641f]'
                  }`}
                >
                  {tag}
                </span>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* Flagged URLs */}
      <h2 className="flex items-center gap-2.5 text-lg font-extrabold tracking-[0.2px] mb-4 text-[#f2f6fc]">
        <span className="w-2 h-2 rounded-full bg-[#3fd0f0] shadow-[0_0_10px_#3fd0f0]"></span>
        Flagged URLs
      </h2>

      <section className="bg-[#121b2b] border border-[#202e45] rounded-[14px] p-6 mb-8">
        {analysisCase.flaggedUrls.length === 0 ? (
          <div className="text-sm text-[#38d98c] flex items-center gap-2 py-4">
            <CheckCircle2 className="w-4 h-4" />
            No suspicious or high-risk URLs detected in message body or headers.
          </div>
        ) : (
          <div className="space-y-3">
            {analysisCase.flaggedUrls.map((item, idx) => (
              <div
                key={idx}
                className="flex items-center gap-3.5 p-4 rounded-xl border border-[#202e45] bg-[#182339] flex-wrap"
              >
                <span
                  className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-extrabold uppercase shrink-0 border ${
                    item.risk === 'HIGH RISK'
                      ? 'text-[#ff7d82] bg-[#301419] border-[#8f2f37]'
                      : item.risk === 'SUSPICIOUS'
                      ? 'text-[#ffc45c] bg-[#2c2110] border-[#8a641f]'
                      : 'text-[#4fe0a0] bg-[#122b20] border-[#267a52]'
                  }`}
                >
                  {item.risk}
                </span>
                <span className="font-mono text-xs md:text-sm text-[#d9e8fa] break-all flex-1 min-w-[230px]">
                  {item.url}
                </span>
                <button
                  onClick={() => handleCopyUrl(item.url)}
                  title="Copy Indicator URL"
                  className="w-7 h-7 rounded-[7px] border border-[#202e45] hover:border-[#3fd0f0] hover:text-[#3fd0f0] text-[#aab9d0] grid place-items-center transition-colors cursor-pointer"
                >
                  <Copy className="w-3.5 h-3.5" />
                </button>
                <div className="w-full text-xs md:text-sm text-[#d8e2f0] pt-1 border-t border-[#202e45]/50">
                  {item.reason}
                </div>
              </div>
            ))}
          </div>
        )}

        <div className="flex items-center gap-2 mt-4 text-xs md:text-sm text-[#d8e2f0]">
          <AlertTriangle className="w-4 h-4 text-[#ffb92e]" />
          {analysisCase.flaggedUrls.length} flagged URL indicators inspected
        </div>
      </section>

      {/* Why This Was Flagged */}
      <h2 className="flex items-center gap-2.5 text-lg font-extrabold tracking-[0.2px] mb-4 text-[#f2f6fc]">
        <span className="w-2 h-2 rounded-full bg-[#3fd0f0] shadow-[0_0_10px_#3fd0f0]"></span>
        Why This Was Flagged
      </h2>

      <section
        className={`rounded-[14px] p-7 border mb-8 ${
          isHighRisk
            ? 'border-[#8f2f37] bg-gradient-to-b from-[#301419] to-[#121b2b]'
            : isSuspicious
            ? 'border-[#8a641f] bg-gradient-to-b from-[#2c2110] to-[#121b2b]'
            : 'border-[#267a52] bg-gradient-to-b from-[#122b20] to-[#121b2b]'
        }`}
      >
        <h3
          className={`text-lg font-extrabold flex items-center gap-2.5 mb-3 ${
            isHighRisk ? 'text-[#ff8d91]' : isSuspicious ? 'text-[#ffd269]' : 'text-[#4fe0a0]'
          }`}
        >
          <ShieldAlert className="w-5 h-5 stroke-[2]" />
          Forensic Threat Rationale
        </h3>
        <p className="text-[#f2f6fc] text-base leading-relaxed">
          {analysisCase.whyFlagged.explanation}
        </p>
        <div className="flex flex-wrap gap-2.5 mt-4">
          {analysisCase.whyFlagged.evidence.map((ev, i) => (
            <span
              key={i}
              className={`inline-flex items-center gap-2 text-xs md:text-[13.5px] font-bold px-3 py-1.5 rounded-lg border ${
                ev.type === 'fail'
                  ? 'text-[#ffe2e3] bg-[#ff5d63]/10 border-[#ff5d63]/35'
                  : ev.type === 'warn'
                  ? 'text-[#fff4dc] bg-[#ffb92e]/10 border-[#ffb92e]/35'
                  : 'text-[#d9ffe9] bg-[#38d98c]/10 border-[#38d98c]/30'
              }`}
            >
              {ev.type === 'fail' ? (
                <XCircle className="w-3.5 h-3.5 text-[#ff5d63]" />
              ) : ev.type === 'warn' ? (
                <AlertTriangle className="w-3.5 h-3.5 text-[#ffb92e]" />
              ) : (
                <CheckCircle2 className="w-3.5 h-3.5 text-[#38d98c]" />
              )}
              {ev.text}
            </span>
          ))}
        </div>
      </section>

      {/* AI-Assisted Content Analysis */}
      <h2 className="flex items-center gap-2.5 text-lg font-extrabold tracking-[0.2px] mb-4 text-[#f2f6fc]">
        <span className="w-2 h-2 rounded-full bg-[#a78bfa] shadow-[0_0_10px_#a78bfa]"></span>
        AI-Assisted Content Analysis
        <span className="text-xs font-mono font-bold px-2 py-0.5 rounded-full bg-[#1e1b4b] border border-[#4338ca] text-[#c4b5fd]">
          Gemini 3.8 Flash
        </span>
      </h2>

      <section className="bg-[#121b2b] border border-[#202e45] rounded-[14px] p-6 mb-8 shadow-[0_4px_20px_rgba(0,0,0,0.25)]">
        {/* Executive Content Assessment */}
        <div className="mb-5 pb-5 border-b border-[#202e45]">
          <div className="flex items-center justify-between gap-3 flex-wrap mb-2">
            <div className="text-xs font-extrabold text-[#aab9d0] tracking-wider uppercase flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-[#a78bfa]" />
              Social-Engineering &amp; Persuasion Evaluation
            </div>
            {analysisCase.aiContentAnalysis?.contentAnalysisAvailable ? (
              <span className="text-xs font-bold text-[#38d98c] flex items-center gap-1.5 bg-[#122b20] border border-[#267a52] px-2.5 py-0.5 rounded-full">
                <CheckCircle2 className="w-3.5 h-3.5" />
                Content Analyzed
              </span>
            ) : (
              <span className="text-xs font-bold text-[#ffb92e] flex items-center gap-1.5 bg-[#2c2110] border border-[#8a641f] px-2.5 py-0.5 rounded-full">
                <AlertTriangle className="w-3.5 h-3.5" />
                Body Unavailable
              </span>
            )}
          </div>
          <p className="text-sm md:text-base text-[#f2f6fc] leading-relaxed">
            {analysisCase.aiContentAnalysis?.overallAssessment ||
              (analysisCase.aiContentAnalysis?.contentAnalysisAvailable === false
                ? 'Email body unavailable — content-based analysis could not be performed.'
                : 'No significant phishing or social-engineering indicators were detected in the supplied email content.')}
          </p>
        </div>

        {/* Structured Findings List */}
        {!analysisCase.aiContentAnalysis || !analysisCase.aiContentAnalysis.contentAnalysisAvailable ? (
          <div className="p-4 rounded-xl border border-[#202e45] bg-[#0e1624] text-xs md:text-sm text-[#aab9d0] flex items-center gap-3">
            <AlertTriangle className="w-4 h-4 text-[#ffb92e] shrink-0" />
            <span>Email body unavailable — content-based analysis could not be performed (+0 risk points applied).</span>
          </div>
        ) : analysisCase.aiContentAnalysis.findings.length === 0 ? (
          <div className="p-4 rounded-xl border border-[#267a52]/40 bg-[#122b20]/40 text-xs md:text-sm text-[#4fe0a0] flex items-center gap-3">
            <CheckCircle2 className="w-4 h-4 text-[#38d98c] shrink-0" />
            <span>No significant phishing or social-engineering indicators were detected in the supplied email content (+0 risk points).</span>
          </div>
        ) : (
          <div className="space-y-3">
            <div className="text-xs font-extrabold text-[#aab9d0] tracking-wider uppercase mb-1">
              Detected Threat Categories ({analysisCase.aiContentAnalysis.findings.length})
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
              {analysisCase.aiContentAnalysis.findings.map((finding, idx) => (
                <div
                  key={idx}
                  className="p-4 rounded-xl border border-[#202e45] bg-[#182339] flex flex-col justify-between"
                >
                  <div className="flex items-center justify-between gap-2 mb-2">
                    <span className="font-extrabold text-sm text-[#f2f6fc] tracking-[0.2px]">
                      {finding.category}
                    </span>
                    <div className="flex items-center gap-1.5">
                      <span
                        className={`text-[11px] font-extrabold uppercase px-2 py-0.5 rounded border ${
                          finding.severity === 'high'
                            ? 'text-[#ff7d82] bg-[#301419] border-[#8f2f37]'
                            : finding.severity === 'medium'
                            ? 'text-[#ffc45c] bg-[#2c2110] border-[#8a641f]'
                            : 'text-[#8fe8ff] bg-[#0c2834] border-[#1d5c76]'
                        }`}
                      >
                        {finding.severity}
                      </span>
                      <span className="text-[11px] font-mono text-[#aab9d0] px-1.5 py-0.5 rounded bg-[#0f1725] border border-[#202e45]">
                        {finding.confidence}% conf
                      </span>
                    </div>
                  </div>
                  <p className="text-xs md:text-sm text-[#d8e2f0] leading-relaxed">
                    {finding.evidence}
                  </p>
                </div>
              ))}
            </div>
          </div>
        )}

        <div className="mt-5 pt-3 border-t border-[#202e45]/60 flex items-center justify-between text-xs text-[#aab9d0] flex-wrap gap-2">
          <span>
            Strict evidence boundary: Technical headers (SPF, DKIM, DMARC, Domain Age, IPs, Relays) are evaluated deterministically and never altered by AI.
          </span>
          <span className="font-mono text-[#3fd0f0]">Max Risk Contribution: +15 pts</span>
        </div>
      </section>

      {/* Campaign Infrastructure Correlation Section */}
      <section className="bg-[#121b2b] border border-[#202e45] rounded-[14px] p-6 mb-8 shadow-[0_12px_34px_rgba(0,0,0,0.38)]">
        <div className="flex items-center justify-between flex-wrap gap-3 mb-4">
          <div className="flex items-center gap-2.5">
            <Network className="w-5 h-5 text-[#a855f7]" />
            <h2 className="text-lg font-extrabold text-[#f2f6fc] tracking-[0.2px]">
              Campaign Correlation &amp; Historical Infrastructure
            </h2>
          </div>
          <button
            onClick={() => onNavigate('graph')}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold text-[#f3e8ff] bg-[#2e1065] border border-[#9333ea] hover:bg-[#3b1d6e] transition-colors cursor-pointer"
          >
            Open Investigation Graph →
          </button>
        </div>

        {analysisCase.correlation?.campaignCandidate?.detected ? (
          <div className="p-4 rounded-xl border border-[#9333ea]/50 bg-[#1f1635] space-y-3">
            <div className="flex items-center justify-between gap-2 flex-wrap">
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-[#c084fc] animate-pulse"></span>
                <span className="font-extrabold text-sm text-[#f3e8ff]">
                  Campaign Candidate Detected ({analysisCase.correlation.campaignCandidate.confidenceScore}% Confidence)
                </span>
              </div>
              <span className="text-xs font-mono text-[#d8b4fe] bg-[#3b1d6e] px-2.5 py-0.5 rounded-full border border-[#a855f7]">
                {analysisCase.correlation.campaignCandidate.correlatedCaseIds.length} Linked Case(s)
              </span>
            </div>

            <p className="text-xs text-[#e9d5ff]/90 leading-relaxed">
              {analysisCase.correlation.campaignCandidate.disclaimer}
            </p>

            <div className="flex flex-wrap gap-2 pt-2 border-t border-[#3b1d6e]">
              <span className="text-xs font-semibold text-[#c084fc]">Shared Infrastructure:</span>
              {analysisCase.correlation.campaignCandidate.sharedEntities.map((se, idx) => (
                <span
                  key={idx}
                  className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono bg-[#2e1065] border border-[#9333ea] text-[#f3e8ff]"
                >
                  <span className="text-[#c084fc] font-sans">{se.type}:</span> {se.value}
                </span>
              ))}
            </div>
          </div>
        ) : (analysisCase.correlation?.totalAnalyzedCasesCount || 1) <= 1 ? (
          <div className="p-4 rounded-xl border border-[#202e45] bg-[#0e1624] text-xs text-[#aab9d0] flex items-center gap-3">
            <Info className="w-4 h-4 text-[#3fd0f0] shrink-0" />
            <span>
              Campaign correlation requires comparable analyzed cases. Analyze more emails to identify recurring infrastructure across incidents.
            </span>
          </div>
        ) : (
          <div className="p-4 rounded-xl border border-[#202e45] bg-[#0e1624] text-xs text-[#aab9d0] flex items-center gap-3">
            <CheckCircle2 className="w-4 h-4 text-[#38d98c] shrink-0" />
            <span>
              No meaningful shared infrastructure detected against {analysisCase.correlation?.totalAnalyzedCasesCount || 0} historical cases.
            </span>
          </div>
        )}
      </section>

      {/* Technical Details Accordion */}
      <h2 className="flex items-center gap-2.5 text-lg font-extrabold tracking-[0.2px] mb-4 text-[#f2f6fc]">
        <span className="w-2 h-2 rounded-full bg-[#3fd0f0] shadow-[0_0_10px_#3fd0f0]"></span>
        Technical Details
      </h2>

      <details className="bg-[#121b2b] border border-[#202e45] rounded-[14px] overflow-hidden mb-8 group">
        <summary className="list-none cursor-pointer p-5 font-extrabold text-sm md:text-base flex items-center justify-between text-[#f2f6fc] select-none hover:bg-white/[0.02] transition-colors">
          <div className="flex items-center gap-2.5">
            <FileText className="w-4 h-4 text-[#3fd0f0]" />
            View Technical RFC Details &amp; Observed Headers
          </div>
          <ChevronDown className="w-4 h-4 text-[#aab9d0] transition-transform duration-200 group-open:rotate-180" />
        </summary>
        <div className="bg-[#0a101c] border-t border-[#202e45] p-5 font-mono text-xs text-[#bfd2e8] leading-loose whitespace-pre-wrap break-all">
          <div className="text-[#8fe8ff] font-bold mb-2">=== RAW EMAIL HEADERS ===</div>
          {analysisCase.technicalDetails.rawHeaders}

          <div className="text-[#8fe8ff] font-bold mt-4 mb-2">
            === RECEIVED CHAIN (Oldest → Newest) ===
          </div>
          {analysisCase.technicalDetails.receivedChain.map((line, i) => (
            <div key={i} className="mb-1">
              [Hop {i + 1}] {line}
            </div>
          ))}

          <div className="text-[#8fe8ff] font-bold mt-4 mb-2">=== IP ADDRESSES OBSERVED ===</div>
          {analysisCase.technicalDetails.observedIps.map((ip, i) => (
            <div key={i}>
              <span className="text-[#ffb92e] font-bold">{ip.ip}</span> — {ip.note}
            </div>
          ))}

          <div className="text-[#8fe8ff] font-bold mt-4 mb-1">=== AUTHENTICATION BREAKDOWN ===</div>
          <div>SPF Details: {analysisCase.technicalDetails.spfDetails}</div>
          <div>DKIM Details: {analysisCase.technicalDetails.dkimDetails}</div>
          <div>DMARC Details: {analysisCase.technicalDetails.dmarcDetails}</div>
        </div>
      </details>

      {/* Export / Continue Row */}
      <section className="flex flex-wrap items-center justify-center gap-3 p-7 rounded-[14px] border border-dashed border-[#31445f] bg-[#182339]">
        <span className="text-sm font-semibold text-[#d8e2f0]">Continue investigation:</span>
        <button
          onClick={() => onNavigate('trace')}
          className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs md:text-sm font-bold bg-transparent border border-[#31445f] text-[#d8e2f0] hover:border-[#3fd0f0] hover:text-[#3fd0f0] transition-colors cursor-pointer"
        >
          <Route className="w-3.5 h-3.5" />
          Relay Trace
        </button>
        <button
          onClick={() => onNavigate('graph')}
          className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs md:text-sm font-bold bg-transparent border border-[#31445f] text-[#d8e2f0] hover:border-[#3fd0f0] hover:text-[#3fd0f0] transition-colors cursor-pointer"
        >
          <Network className="w-3.5 h-3.5" />
          Investigation Graph
        </button>
        <button
          onClick={() => onNavigate('report')}
          className="inline-flex items-center gap-1.5 px-5 py-2 rounded-xl text-xs md:text-sm font-bold bg-gradient-to-b from-[#2ec9ec] to-[#17a7d8] text-[#06131c] shadow-[0_4px_18px_rgba(23,167,216,0.35)] hover:brightness-110 transition-colors cursor-pointer"
        >
          <FileText className="w-3.5 h-3.5 stroke-[2.2]" />
          Generate Forensic Report
        </button>
        <button
          onClick={() => onNavigate('analyzer')}
          className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs md:text-sm font-bold bg-transparent border border-[#31445f] text-[#d8e2f0] hover:border-[#3fd0f0] hover:text-[#3fd0f0] transition-colors cursor-pointer"
        >
          + New Analysis
        </button>
      </section>
    </div>
  );
};
