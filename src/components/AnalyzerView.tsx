import React, { useState, useRef } from 'react';
import {
  ShieldAlert,
  Upload,
  FileText,
  AlertTriangle,
  Search,
  Lock,
  Sparkles,
  Zap,
  CheckCircle2,
  XCircle,
  FileCode2,
} from 'lucide-react';
import type { SampleEmailPreset } from '../types';

interface AnalyzerViewProps {
  onAnalyze: (rawContent: string) => Promise<void>;
  isLoading: boolean;
  presets: SampleEmailPreset[];
}

export const AnalyzerView: React.FC<AnalyzerViewProps> = ({
  onAnalyze,
  isLoading,
  presets,
}) => {
  const [activeTab, setActiveTab] = useState<'headers' | 'upload'>('headers');
  const [rawText, setRawText] = useState<string>(
    presets[0]?.headers ||
      `From: "Account Security" <support@example-domain.com>
To: user@example.com
Subject: Urgent account verification required
Date: Sat, 12 Sep 2026 12:41:52 +0000

Received: from mx2.recipient-isp.example.net (mx2.recipient-isp.example.net [198.51.100.27])
        by mail.example.com with ESMTP id A3f9Kq2
Received: from relay.mailnode.example.net (relay.mailnode.example.net [103.16.201.44])
Received: from mx1.example-domain.com (mx1.example-domain.com [185.204.48.131])

Return-Path: <support@example-domain.com>
Message-ID: <A3f9Kq2@example-domain.com>

Authentication-Results: mx2.recipient-isp.example.net;
        spf=fail (sender IP 185.204.48.131 not authorized) smtp.mailfrom=support@example-domain.com;
        dkim=pass header.d=example-domain.com;
        dmarc=fail (p=reject) header.from=example-domain.com

DKIM-Signature: v=1; a=rsa-sha256; d=example-domain.com; s=s1;
        bh=Za3x...; h=from:to:subject:date;
        i=@example-domain.com

Dear user, please verify your credentials at: https://secure-login.example.net/session/refresh`
  );

  const [isDragging, setIsDragging] = useState<boolean>(false);
  const [uploadedFileName, setUploadedFileName] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const handlePresetSelect = (preset: SampleEmailPreset) => {
    setRawText(preset.headers);
    setUploadedFileName(null);
    setActiveTab('headers');
  };

  const handleFileDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) {
      processFile(file);
    }
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      processFile(file);
    }
  };

  const processFile = (file: File) => {
    setUploadedFileName(file.name);
    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      if (content) {
        setRawText(content);
      }
    };
    reader.readAsText(file);
  };

  const handleSubmit = async () => {
    if (!rawText.trim() || isLoading) return;
    await onAnalyze(rawText);
  };

  return (
    <div className="w-full max-w-[960px] mx-auto py-6">
      {/* Hero Section */}
      <section className="text-center mb-10">
        <div className="inline-flex items-center gap-2 text-[#3fd0f0] text-xs font-extrabold tracking-[2.2px] uppercase mb-3 px-3 py-1 rounded-full bg-[#0e2733] border border-[#1f5a72]">
          <Zap className="w-3.5 h-3.5" />
          Email Threat Intelligence
        </div>
        <h1 className="text-3xl md:text-[40px] font-extrabold tracking-[-0.5px] leading-tight text-[#f2f6fc]">
          Analyze an Email. <em className="italic not-italic text-[#3fd0f0]">Understand the Threat.</em>
        </h1>
        <p className="text-[#d8e2f0] text-base md:text-[17px] mt-3.5 max-w-2xl mx-auto leading-relaxed">
          Analyze raw email headers or upload an .eml file to detect suspicious authentication results,
          impersonated domains, URLs, and indicators of compromise.
        </p>
      </section>

      {/* Quick sample preset picker */}
      <div className="mb-4">
        <div className="flex items-center justify-between gap-2 mb-2 px-1">
          <span className="text-xs font-bold text-[#aab9d0] uppercase tracking-wider flex items-center gap-1.5">
            <Sparkles className="w-3.5 h-3.5 text-[#3fd0f0]" />
            Test With Ready-Made Attack & Clean Samples:
          </span>
          {uploadedFileName && (
            <span className="text-xs font-mono text-[#38d98c] flex items-center gap-1">
              <CheckCircle2 className="w-3.5 h-3.5" />
              File loaded: {uploadedFileName}
            </span>
          )}
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
          {presets.map((preset) => (
            <button
              key={preset.id}
              onClick={() => handlePresetSelect(preset)}
              className="flex flex-col text-left p-3 rounded-xl bg-[#121b2b] border border-[#202e45] hover:border-[#3fd0f0] hover:bg-[#182339] transition-all cursor-pointer group"
            >
              <div className="flex items-center justify-between gap-2 mb-1">
                <span className="font-bold text-xs text-[#f2f6fc] group-hover:text-[#3fd0f0] truncate">
                  {preset.title.split('·')[0]}
                </span>
                <span
                  className={`text-[10px] font-extrabold px-2 py-0.5 rounded-full uppercase border shrink-0 ${
                    preset.badgeCls === 'fail'
                      ? 'text-[#ff7d82] bg-[#301419] border-[#8f2f37]'
                      : preset.badgeCls === 'warn'
                      ? 'text-[#ffc45c] bg-[#2c2110] border-[#8a641f]'
                      : 'text-[#4fe0a0] bg-[#122b20] border-[#267a52]'
                  }`}
                >
                  {preset.badge}
                </span>
              </div>
              <p className="text-[11.5px] text-[#aab9d0] line-clamp-2 leading-snug">
                {preset.description}
              </p>
            </button>
          ))}
        </div>
      </div>

      {/* Main Analysis Input Card */}
      <section className="bg-[#121b2b] border border-[#202e45] rounded-[14px] shadow-[0_12px_34px_rgba(0,0,0,0.38)] overflow-hidden">
        <div className="flex gap-1 border-b border-[#202e45] px-4 pt-2">
          <button
            onClick={() => setActiveTab('headers')}
            className={`flex items-center gap-2 px-4 py-3 text-sm font-extrabold border-b-2 cursor-pointer transition-colors ${
              activeTab === 'headers'
                ? 'text-[#3fd0f0] border-[#3fd0f0]'
                : 'text-[#aab9d0] border-transparent hover:text-[#f2f6fc]'
            }`}
          >
            <FileCode2 className="w-4 h-4" />
            Paste Email Headers
          </button>
          <button
            onClick={() => setActiveTab('upload')}
            className={`flex items-center gap-2 px-4 py-3 text-sm font-extrabold border-b-2 cursor-pointer transition-colors ${
              activeTab === 'upload'
                ? 'text-[#3fd0f0] border-[#3fd0f0]'
                : 'text-[#aab9d0] border-transparent hover:text-[#f2f6fc]'
            }`}
          >
            <Upload className="w-4 h-4" />
            Upload .eml File
          </button>
        </div>

        <div className="p-6">
          {activeTab === 'headers' ? (
            <div>
              <div className="flex items-center justify-between mb-2">
                <label className="text-xs font-semibold text-[#aab9d0]">
                  Raw RFC 822 / 2822 Headers & Email Content:
                </label>
                <button
                  onClick={() => setRawText('')}
                  className="text-xs text-[#aab9d0] hover:text-[#ff5d63] cursor-pointer transition-colors"
                >
                  Clear
                </button>
              </div>
              <textarea
                value={rawText}
                onChange={(e) => setRawText(e.target.value)}
                spellCheck={false}
                rows={12}
                className="w-full min-h-[290px] bg-[#0a101c] border border-[#31445f] rounded-xl text-[#d7e5f5] font-mono text-xs md:text-[13px] leading-relaxed p-4 resize-y outline-none focus:border-[#3fd0f0] focus:ring-2 focus:ring-[#3fd0f0]/20 transition-all"
                placeholder="From: sender@domain.com&#10;To: recipient@domain.com&#10;Subject: Urgent notice...&#10;Authentication-Results: ...&#10;Received: from ..."
              />
            </div>
          ) : (
            <div>
              <input
                ref={fileInputRef}
                type="file"
                accept=".eml,.msg,.txt"
                onChange={handleFileSelect}
                className="hidden"
              />
              <div
                onDragOver={(e) => {
                  e.preventDefault();
                  setIsDragging(true);
                }}
                onDragLeave={() => setIsDragging(false)}
                onDrop={handleFileDrop}
                onClick={() => fileInputRef.current?.click()}
                className={`min-h-[290px] border-2 border-dashed rounded-xl flex flex-col items-center justify-center gap-3 p-8 text-center cursor-pointer transition-all bg-[#0a101c] ${
                  isDragging
                    ? 'border-[#3fd0f0] bg-[#3fd0f0]/10 text-[#3fd0f0]'
                    : 'border-[#31445f] hover:border-[#3fd0f0]/60 text-[#d8e2f0]'
                }`}
              >
                <div className="w-16 h-16 rounded-2xl bg-[#121b2b] border border-[#202e45] grid place-items-center text-[#3fd0f0]">
                  <Upload className="w-8 h-8 stroke-[1.8]" />
                </div>
                <div>
                  <strong className="text-lg font-bold text-[#f2f6fc] block mb-1">
                    {uploadedFileName ? `${uploadedFileName} (Ready)` : 'Drop your .eml file here'}
                  </strong>
                  <span className="text-sm text-[#aab9d0]">or browse from your device</span>
                </div>
                <span className="text-xs text-[#aab9d0] border border-[#202e45] bg-[#121b2b] px-3 py-1 rounded-md">
                  Supported format: .eml, raw RFC email text
                </span>
              </div>
            </div>
          )}

          <div className="flex flex-col sm:flex-row items-center justify-between gap-4 mt-5 pt-4 border-t border-[#202e45]">
            <div className="text-xs text-[#aab9d0] flex items-center gap-1.5">
              <ShieldAlert className="w-4 h-4 text-[#38d98c]" />
              Isolated forensic execution · Real-time verification & graph analysis
            </div>

            <button
              onClick={handleSubmit}
              disabled={isLoading || !rawText.trim()}
              className="w-full sm:w-auto inline-flex items-center justify-center gap-2.5 rounded-xl font-bold text-sm md:text-[15px] px-6 py-3 bg-gradient-to-b from-[#2ec9ec] to-[#17a7d8] text-[#06131c] shadow-[0_4px_18px_rgba(23,167,216,0.35)] hover:brightness-110 disabled:opacity-50 disabled:cursor-not-allowed transition-all cursor-pointer"
            >
              {isLoading ? (
                <>
                  <svg
                    className="animate-spin h-4 w-4 text-[#06131c]"
                    xmlns="http://www.w3.org/2000/svg"
                    fill="none"
                    viewBox="0 0 24 24"
                  >
                    <circle
                      className="opacity-25"
                      cx="12"
                      cy="12"
                      r="10"
                      stroke="currentColor"
                      strokeWidth="4"
                    ></circle>
                    <path
                      className="opacity-75"
                      fill="currentColor"
                      d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                    ></path>
                  </svg>
                  Analyzing Threat Artifacts...
                </>
              ) : (
                <>
                  <ShieldAlert className="w-4 h-4 stroke-[2.2]" />
                  Analyze Email
                </>
              )}
            </button>
          </div>
        </div>
      </section>

      {/* Feature 3-Grid */}
      <section className="grid grid-cols-1 md:grid-cols-3 gap-5 mt-6">
        <div className="bg-[#121b2b] border border-[#202e45] rounded-[14px] p-6 hover:border-[#31445f] transition-all">
          <div className="w-10 h-10 rounded-[10px] grid place-items-center mb-3 bg-[#122b20] border border-[#267a52] text-[#38d98c]">
            <ShieldAlert className="w-5 h-5 stroke-[2]" />
          </div>
          <h3 className="text-base font-extrabold text-[#f2f6fc] mb-1">
            Authentication Analysis
          </h3>
          <p className="text-sm text-[#d8e2f0]">
            Cryptographic SPF, DKIM signature verification, and DMARC alignment policy review.
          </p>
        </div>

        <div className="bg-[#121b2b] border border-[#202e45] rounded-[14px] p-6 hover:border-[#31445f] transition-all">
          <div className="w-10 h-10 rounded-[10px] grid place-items-center mb-3 bg-[#2c2110] border border-[#8a641f] text-[#ffb92e]">
            <AlertTriangle className="w-5 h-5 stroke-[2]" />
          </div>
          <h3 className="text-base font-extrabold text-[#f2f6fc] mb-1">
            Threat Intelligence
          </h3>
          <p className="text-sm text-[#d8e2f0]">
            Identify lookalike domains, suspicious IP networks, blocklists, and credential-harvesting links.
          </p>
        </div>

        <div className="bg-[#121b2b] border border-[#202e45] rounded-[14px] p-6 hover:border-[#31445f] transition-all">
          <div className="w-10 h-10 rounded-[10px] grid place-items-center mb-3 bg-[#0e2733] border border-[#1f5a72] text-[#3fd0f0]">
            <Search className="w-5 h-5 stroke-[2]" />
          </div>
          <h3 className="text-base font-extrabold text-[#f2f6fc] mb-1">
            AI Investigation
          </h3>
          <p className="text-sm text-[#d8e2f0]">
            Understand exactly why the email was flagged in plain language with key forensic indicators.
          </p>
        </div>
      </section>

      {/* About Section */}
      <section id="about" className="bg-[#121b2b] border border-[#202e45] rounded-[14px] p-6 mt-6">
        <div className="flex items-center gap-2.5 text-base font-extrabold text-[#f2f6fc]">
          <FileText className="w-4 h-4 text-[#3fd0f0]" />
          About ThreatLens
        </div>
        <p className="text-sm text-[#d8e2f0] mt-2.5 leading-relaxed">
          ThreatLens is an AI-powered email threat analysis dashboard. It parses RFC 822 headers, verifies
          cryptographic SPF, DKIM, and DMARC alignment, inspects sender infrastructure, traces the
          message's multi-hop relay journey across mail transfer agents, builds an interactive entity relationship
          investigation graph, and generates actionable forensic dossiers suitable for SOC response teams.
        </p>
        <div className="flex flex-wrap gap-2.5 mt-4">
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold text-[#6fe1ff] bg-[#0e2733] border border-[#1f5a72]">
            SPF · DKIM · DMARC
          </span>
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold text-[#ffc45c] bg-[#2c2110] border border-[#8a641f]">
            Domain &amp; URL Intelligence
          </span>
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold text-[#4fe0a0] bg-[#122b20] border border-[#267a52]">
            Relay Trace &amp; Geo Mapping
          </span>
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold text-[#f2f6fc] bg-[#182339] border border-[#31445f]">
            Graph Relationship Forensics
          </span>
        </div>
      </section>

      {/* Privacy Guarantee Card */}
      <section className="bg-[#121b2b] border border-[#202e45] rounded-[14px] p-5 mt-5 flex items-center gap-3.5">
        <Lock className="w-5 h-5 text-[#38d98c] shrink-0" />
        <p className="text-xs md:text-sm text-[#d8e2f0] m-0">
          Your email artifacts are analyzed in isolated sandbox instances. Sensitive parameters and tokens
          are protected server-side with enterprise privacy safeguards.
        </p>
      </section>
    </div>
  );
};
