import React from 'react';
import { ShieldCheck, Cpu, Database, Eye, Terminal, Lock, CheckCircle2 } from 'lucide-react';

interface AboutViewProps {
  onNavigate: (view: 'analyzer' | 'results' | 'trace' | 'graph' | 'report' | 'about') => void;
}

export const AboutView: React.FC<AboutViewProps> = ({ onNavigate }) => {
  return (
    <div className="w-full max-w-[960px] mx-auto py-4">
      <section className="text-center mb-10">
        <div className="inline-flex items-center gap-2 text-[#3fd0f0] text-xs font-extrabold tracking-[2.2px] uppercase mb-3 px-3 py-1 rounded-full bg-[#0e2733] border border-[#1f5a72]">
          <Cpu className="w-3.5 h-3.5" />
          Forensic Architecture
        </div>
        <h1 className="text-3xl md:text-4xl font-extrabold tracking-[-0.5px] text-[#f2f6fc]">
          About ThreatLens
        </h1>
        <p className="text-base text-[#d8e2f0] mt-3 max-w-xl mx-auto leading-relaxed">
          ThreatLens is an AI-powered email threat analysis and digital forensics suite designed for Security Operations Centers (SOC), incident responders, and organizations defending against modern phishing attacks.
        </p>
      </section>

      <section className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
        <div className="bg-[#121b2b] border border-[#202e45] rounded-[14px] p-6">
          <div className="w-10 h-10 rounded-xl bg-[#0e2733] border border-[#1f5a72] text-[#3fd0f0] grid place-items-center mb-3">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <h2 className="text-lg font-extrabold text-[#f2f6fc] mb-2">Cryptographic Email Verification</h2>
          <p className="text-sm text-[#d8e2f0] leading-relaxed">
            Performs RFC 7208 (SPF), RFC 6376 (DKIM), and RFC 7489 (DMARC) alignment validation. Detects domain spoofing, mismatched envelope sender addresses, and unauthorized mail transfer agent relays.
          </p>
        </div>

        <div className="bg-[#121b2b] border border-[#202e45] rounded-[14px] p-6">
          <div className="w-10 h-10 rounded-xl bg-[#2c2110] border border-[#8a641f] text-[#ffb92e] grid place-items-center mb-3">
            <Eye className="w-5 h-5" />
          </div>
          <h2 className="text-lg font-extrabold text-[#f2f6fc] mb-2">AI-Powered Behavioral Forensics</h2>
          <p className="text-sm text-[#d8e2f0] leading-relaxed">
            Powered by Google Gemini 3.8 Flash, ThreatLens synthesizes complex header artifacts, linguistic urgency markers, brand impersonation signals, and infrastructure anomalies into plain-language incident reasoning.
          </p>
        </div>

        <div className="bg-[#121b2b] border border-[#202e45] rounded-[14px] p-6">
          <div className="w-10 h-10 rounded-xl bg-[#301419] border border-[#8f2f37] text-[#ff5d63] grid place-items-center mb-3">
            <Terminal className="w-5 h-5" />
          </div>
          <h2 className="text-lg font-extrabold text-[#f2f6fc] mb-2">Hop-by-Hop MTA Relay Mapping</h2>
          <p className="text-sm text-[#d8e2f0] leading-relaxed">
            Reconstructs the reverse SMTP path through all intermediate servers, identifying open relays, unexpected geographic routing paths, and latency bottlenecks between sender and recipient mailbox.
          </p>
        </div>

        <div className="bg-[#121b2b] border border-[#202e45] rounded-[14px] p-6">
          <div className="w-10 h-10 rounded-xl bg-[#122b20] border border-[#267a52] text-[#38d98c] grid place-items-center mb-3">
            <Database className="w-5 h-5" />
          </div>
          <h2 className="text-lg font-extrabold text-[#f2f6fc] mb-2">Threat Graph &amp; Dossier Export</h2>
          <p className="text-sm text-[#d8e2f0] leading-relaxed">
            Generates interactive entity-relationship graphs linking suspect IPs, URLs, domains, and associated campaign emails. Exports compliance-ready forensic reports in PDF, Markdown, and JSON.
          </p>
        </div>
      </section>

      <div className="text-center pt-4">
        <button
          onClick={() => onNavigate('analyzer')}
          className="inline-flex items-center gap-2 px-6 py-3 rounded-xl font-bold text-sm bg-gradient-to-b from-[#2ec9ec] to-[#17a7d8] text-[#06131c] shadow-[0_4px_18px_rgba(23,167,216,0.35)] hover:brightness-110 transition-all cursor-pointer"
        >
          Return to Dashboard &amp; Analyze Email
        </button>
      </div>
    </div>
  );
};
