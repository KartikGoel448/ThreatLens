import React, { useState } from 'react';
import {
  Route,
  Globe,
  Server,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Clock,
  ArrowRight,
  ChevronDown,
  Info,
  ShieldAlert,
  MapPin,
  Network,
  Activity,
} from 'lucide-react';
import type { EmailAnalysisCase, RelayHop } from '../types';

interface TraceViewProps {
  analysisCase: EmailAnalysisCase;
  onNavigate: (view: 'analyzer' | 'results' | 'trace' | 'graph' | 'report' | 'about') => void;
}

export const TraceView: React.FC<TraceViewProps> = ({ analysisCase, onNavigate }) => {
  const [selectedHop, setSelectedHop] = useState<number | null>(null);

  const hops = analysisCase.relayTrace || [];

  // Filter hops that have real, verified public-IP coordinates
  const geolocatedHops = hops.filter(
    (h) => h.geo && typeof h.geo.x === 'number' && typeof h.geo.y === 'number'
  );

  return (
    <div className="w-full max-w-[1100px] mx-auto py-2">
      {/* Hero Section */}
      <section className="text-center mb-8">
        <div className="text-xs font-mono font-bold text-[#3fd0f0] uppercase tracking-wider mb-2">
          Case {analysisCase.caseId} · Transmission Forensic Trace
        </div>
        <h1 className="text-2xl md:text-4xl font-extrabold tracking-[-0.5px] text-[#f2f6fc]">
          Email Relay Trace
        </h1>
        <p className="text-sm md:text-base text-[#d8e2f0] mt-2 max-w-xl mx-auto">
          Chronological reconstruction of mail transfer agents (MTAs) parsed strictly from RFC 822 Received headers.
        </p>
      </section>

      {/* Security & Trust Model Callout Banner (Requirement 8) */}
      <div className="bg-[#121b2b] border border-[#263750] rounded-[14px] p-5 mb-8 shadow-sm">
        <div className="flex items-start gap-3.5">
          <div className="p-2 rounded-lg bg-[#3fd0f0]/10 border border-[#3fd0f0]/25 text-[#3fd0f0] shrink-0 mt-0.5">
            <Network className="w-5 h-5" />
          </div>
          <div className="text-xs md:text-sm text-[#d8e2f0] leading-relaxed space-y-2">
            <div className="font-bold text-[#f2f6fc] text-sm md:text-base flex items-center gap-2">
              Forensic Evidence &amp; IP Geolocation Model
            </div>
            <p className="text-[#aab9d0]">
              <strong className="text-[#f2f6fc]">Observed Header Evidence:</strong> Hops are ordered chronologically from origin submission MTA to recipient gateway. Timestamps and hostnames are parsed directly from RFC 822 <code className="text-[#3fd0f0] font-mono px-1 py-0.5 bg-[#0b1120] rounded">Received</code> headers.
            </p>
            <p className="text-[#aab9d0]">
              <strong className="text-[#ffc45c]">Approximate IP Geolocation:</strong> IP geolocation indicates approximate network routing location (ISP/datacenter point of presence), not the exact physical location of the sender. Private, reserved, loopback, and documentation networks (RFC 1918, RFC 5737) cannot be geolocated and are identified without simulated coordinates.
            </p>
            <p className="text-[#aab9d0]">
              <strong className="text-[#ff7d82]">Analytical Distinction:</strong> Earliest visible IP represents the earliest observed MTA header hop, not necessarily an attacker&apos;s physical origin workstation, as upstream proxying or forging prior to initial MTA acceptance may obscure sender origins.
            </p>
          </div>
        </div>
      </div>

      {/* Interactive Map Visualizer */}
      <section className="bg-[#0b1120] border border-[#202e45] rounded-[14px] overflow-hidden mb-8 shadow-[0_12px_34px_rgba(0,0,0,0.38)]">
        <div className="relative">
          <svg className="w-full h-auto block" viewBox="0 0 960 430">
            <defs>
              <pattern id="traceGrid" width="40" height="40" patternUnits="userSpaceOnUse">
                <path d="M40 0H0V40" fill="none" stroke="#182438" strokeWidth="1" />
              </pattern>
            </defs>

            {/* Grid & Backdrop */}
            <rect width="960" height="430" fill="#0b1120" />
            <rect width="960" height="430" fill="url(#traceGrid)" />

            {/* Stylized continent landmasses (Accurately positioned relative to SVG coordinates) */}
            <g fill="#101a2c" stroke="#1b2a42" strokeWidth="1">
              {/* North America */}
              <path d="M120 70 Q 220 50 320 80 Q 300 160 250 200 Q 220 230 190 260 Q 150 200 120 150 Z" />
              {/* South America */}
              <path d="M250 250 Q 320 260 330 330 Q 300 390 260 410 Q 230 350 250 250 Z" />
              {/* Europe & North Africa */}
              <path d="M440 80 Q 560 60 580 140 Q 530 170 470 170 Q 430 140 440 80 Z" />
              {/* Africa */}
              <path d="M460 190 Q 570 190 560 310 Q 510 380 470 330 Q 440 250 460 190 Z" />
              {/* Asia */}
              <path d="M580 70 Q 820 60 850 160 Q 770 230 680 230 Q 610 170 580 70 Z" />
              {/* Australia */}
              <path d="M760 280 Q 860 280 870 360 Q 780 390 740 340 Z" />
            </g>

            {/* Connecting Arc Paths between geolocated hops */}
            {geolocatedHops.length >= 2 && (
              <g fill="none" strokeWidth="2.4">
                {geolocatedHops.slice(0, -1).map((hop, idx) => {
                  const nextHop = geolocatedHops[idx + 1];
                  const p1 = hop.geo!;
                  const p2 = nextHop.geo!;
                  const midX = (p1.x + p2.x) / 2;
                  const arcHeight = Math.min(60, Math.abs(p2.x - p1.x) * 0.2 + 20);
                  const midY = Math.max(30, Math.min(p1.y, p2.y) - arcHeight);

                  const strokeColor =
                    idx === 0 ? '#ffb92e' : idx === geolocatedHops.length - 2 ? '#38d98c' : '#3fd0f0';

                  return (
                    <g key={`path-${idx}`}>
                      <path
                        d={`M ${p1.x} ${p1.y} Q ${midX} ${midY} ${p2.x} ${p2.y}`}
                        stroke={strokeColor}
                        strokeDasharray="6 5"
                        className="animate-[dash_20s_linear_infinite]"
                      />
                    </g>
                  );
                })}
              </g>
            )}

            {/* Render Geolocated Nodes */}
            {geolocatedHops.map((hop, idx) => {
              const geo = hop.geo!;
              const isSelected = selectedHop === idx;
              const isOrigin = idx === 0;
              const isDest = idx === geolocatedHops.length - 1;

              const strokeColor = isOrigin ? '#ffb92e' : isDest ? '#38d98c' : '#3fd0f0';
              const fillColor = isOrigin ? '#2c2110' : isDest ? '#122b20' : '#0e2733';

              return (
                <g
                  key={`node-${idx}`}
                  className="cursor-pointer group"
                  onClick={() => setSelectedHop(idx)}
                >
                  <circle
                    cx={geo.x}
                    cy={geo.y}
                    r={isSelected ? '14' : '11'}
                    fill={fillColor}
                    stroke={strokeColor}
                    strokeWidth="2.5"
                    className="transition-all duration-200"
                  />
                  <circle
                    cx={geo.x}
                    cy={geo.y}
                    r={isSelected ? '26' : '20'}
                    fill="none"
                    stroke={strokeColor}
                    strokeWidth="0.8"
                    opacity={isSelected ? '0.9' : '0.4'}
                  />
                  <text
                    cx={geo.x}
                    cy={geo.y}
                    x={geo.x}
                    y={geo.y - 16}
                    fill={strokeColor}
                    textAnchor="middle"
                    fontWeight="800"
                    fontSize="11"
                    fontFamily="SF Mono, monospace"
                  >
                    Hop {hop.hopNumber} · {hop.geolocation?.city || hop.geolocation?.country || 'Node'}
                  </text>
                  <text
                    x={geo.x}
                    y={geo.y + 24}
                    fill="#8fa7c4"
                    textAnchor="middle"
                    fontSize="10"
                    fontFamily="SF Mono, monospace"
                  >
                    {hop.ip}
                  </text>
                </g>
              );
            })}

            {/* Empty-state or Notice when 0 or 1 geolocated hops */}
            {geolocatedHops.length === 0 && (
              <g>
                <rect x="230" y="165" width="500" height="90" rx="10" fill="#121b2b" stroke="#202e45" strokeWidth="1" />
                <text x="480" y="205" fill="#f2f6fc" textAnchor="middle" fontWeight="bold" fontSize="14">
                  No Public IP Geolocation Coordinates to Plot
                </text>
                <text x="480" y="230" fill="#8fa7c4" textAnchor="middle" fontSize="12">
                  Observed hops utilize private, reserved, or internal mail transport addresses.
                </text>
              </g>
            )}
          </svg>
        </div>

        <div className="flex items-center justify-between gap-3 text-xs text-[#aab9d0] px-5 py-3 border-t border-[#202e45] bg-[#121b2b] flex-wrap">
          <div className="flex items-center gap-2">
            <Info className="w-4 h-4 text-[#3fd0f0] shrink-0" />
            <span>
              {geolocatedHops.length > 0
                ? `Plotting ${geolocatedHops.length} public IP relay hop(s) with verified geographic coordinates.`
                : 'No public IP hops available for map projection.'}
            </span>
          </div>
          <span className="text-[11px] font-mono text-[#8fa7c4]">
            {hops.length} Total Hops in Transmission Chain
          </span>
        </div>
      </section>

      {/* Timeline of Relay Path */}
      <div className="flex items-center justify-between mb-6 flex-wrap gap-2">
        <h2 className="flex items-center gap-2.5 text-lg font-extrabold tracking-[0.2px] text-[#f2f6fc]">
          <span className="w-2 h-2 rounded-full bg-[#3fd0f0] shadow-[0_0_10px_#3fd0f0]"></span>
          Relay Path Timeline (Chronological Order)
        </h2>
        <span className="text-xs text-[#aab9d0] font-mono">
          Oldest (Origin) → Newest (Recipient)
        </span>
      </div>

      <section className="relative pl-9 mb-8">
        {/* Continuous vertical timeline gradient line */}
        <div className="absolute left-3.5 top-3 bottom-4 w-0.5 bg-gradient-to-b from-[#ffb92e] via-[#3fd0f0] to-[#38d98c]"></div>

        <div className="space-y-6">
          {hops.map((hop, index) => {
            const isHot = hop.role === 'SUSPICIOUS';
            const isWarm = hop.role === 'SOURCE' || hop.role === 'WATCH';
            const isClean = hop.role === 'TRUSTED' || hop.role === 'DELIVERED';
            const isSelected = selectedHop === index;

            return (
              <div key={index} className="relative group">
                {/* Timeline node dot */}
                <div
                  className={`absolute -left-[32px] top-4.5 w-3.5 h-3.5 rounded-full border-2 border-[#0a0e17] transition-transform ${
                    isSelected ? 'scale-125 ring-2 ring-[#3fd0f0]' : ''
                  } ${
                    isHot
                      ? 'bg-[#ff5d63] shadow-[0_0_13px_rgba(255,93,99,0.8)]'
                      : isWarm
                      ? 'bg-[#ffb92e] shadow-[0_0_10px_rgba(255,185,46,0.6)]'
                      : 'bg-[#38d98c]'
                  }`}
                ></div>

                {/* Hop Card */}
                <div
                  onClick={() => setSelectedHop(index)}
                  className={`p-5 rounded-xl border bg-[#182339] cursor-pointer transition-all ${
                    isSelected
                      ? 'border-[#3fd0f0] ring-1 ring-[#3fd0f0]/40 shadow-lg'
                      : 'border-[#202e45] hover:border-[#31445f]'
                  }`}
                >
                  <div className="flex justify-between items-start gap-3 flex-wrap">
                    <div>
                      <div className="text-base font-extrabold text-[#f2f6fc] flex items-center gap-2">
                        {hop.name}
                        <span className="text-xs font-mono text-[#3fd0f0] font-bold px-1.5 py-0.5 bg-[#3fd0f0]/10 rounded border border-[#3fd0f0]/20">
                          Hop {hop.hopNumber}
                        </span>
                        {hop.ipType && (
                          <span className={`text-[11px] font-mono px-1.5 py-0.5 rounded border ${
                            hop.ipType === 'PUBLIC'
                              ? 'text-[#3fd0f0] bg-[#3fd0f0]/10 border-[#3fd0f0]/30'
                              : 'text-[#ffc45c] bg-[#ffc45c]/10 border-[#ffc45c]/30'
                          }`}>
                            {hop.ipType}
                          </span>
                        )}
                      </div>
                      <div className="font-mono text-xs md:text-sm mt-1 text-[#d9e8fa]">
                        <span className="text-[#8fa7c4]">MTA Host:</span> {hop.host}
                      </div>
                      {hop.sendingHostname && hop.sendingHostname !== 'Unavailable' && hop.sendingHostname !== hop.host && (
                        <div className="font-mono text-xs text-[#aab9d0] mt-0.5">
                          <span className="text-[#8fa7c4]">Sending Host:</span> {hop.sendingHostname}
                        </div>
                      )}
                    </div>

                    <span
                      className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-extrabold uppercase border ${
                        hop.role === 'SUSPICIOUS'
                          ? 'text-[#ff7d82] bg-[#301419] border-[#8f2f37]'
                          : hop.role === 'WATCH' || hop.role === 'SOURCE'
                          ? 'text-[#ffc45c] bg-[#2c2110] border-[#8a641f]'
                          : 'text-[#4fe0a0] bg-[#122b20] border-[#267a52]'
                      }`}
                    >
                      {hop.role}
                    </span>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3 mt-4 pt-3 border-t border-[#202e45] text-xs md:text-[13px]">
                    <div>
                      <span className="text-[#8fa7c4] block text-[11px] uppercase font-bold">IP Address</span>
                      <strong className="font-mono text-[#f2f6fc]">{hop.ip}</strong>
                    </div>

                    <div>
                      <span className="text-[#8fa7c4] block text-[11px] uppercase font-bold">Approximate Location</span>
                      <span className={hop.geolocation?.status === 'SUCCESS' ? 'text-[#f2f6fc]' : 'text-[#8fa7c4] italic'}>
                        {hop.location}
                      </span>
                    </div>

                    <div>
                      <span className="text-[#8fa7c4] block text-[11px] uppercase font-bold">Header Timestamp</span>
                      <span className="text-[#f2f6fc] font-mono text-xs">{hop.timestamp}</span>
                    </div>

                    <div>
                      <span className="text-[#8fa7c4] block text-[11px] uppercase font-bold">Transit Delay</span>
                      <span className={`font-mono text-xs font-bold ${
                        hop.delayFromPreviousHop?.includes('+') ? 'text-[#38d98c]' : 'text-[#d8e2f0]'
                      }`}>
                        {hop.delayFromPreviousHop || 'Transit delay unavailable'}
                      </span>
                    </div>
                  </div>

                  <div className="flex flex-wrap gap-x-6 gap-y-2 mt-3 pt-3 border-t border-[#202e45]/70 text-xs">
                    <div>
                      <span className="text-[#8fa7c4] mr-1.5 font-semibold">SMTP Info:</span>
                      <span className={hop.response === 'SMTP response unavailable' ? 'text-[#8fa7c4] italic' : 'font-mono text-[#38d98c]'}>
                        {hop.response}
                      </span>
                    </div>

                    {hop.geolocation?.isp && (
                      <div>
                        <span className="text-[#8fa7c4] mr-1.5 font-semibold">ISP:</span>
                        <span className="text-[#d8e2f0]">{hop.geolocation.isp}</span>
                      </div>
                    )}

                    {hop.geolocation?.asn && (
                      <div>
                        <span className="text-[#8fa7c4] mr-1.5 font-semibold">ASN:</span>
                        <span className="font-mono text-[#3fd0f0]">{hop.geolocation.asn}</span>
                      </div>
                    )}

                    <div className="basis-full mt-1">
                      <span className="text-[#8fa7c4] mr-1.5 font-semibold">Forensic Rationale:</span>
                      <span className="text-[#d8e2f0]">{hop.reason}</span>
                    </div>
                  </div>

                  {hop.rawHeader && (
                    <div className="mt-3 pt-2 border-t border-[#202e45]/40 font-mono text-[11px] text-[#7187a5] bg-[#0c1322] p-2.5 rounded break-all">
                      <span className="text-[#3fd0f0] select-none block mb-0.5 font-bold">RFC 822 Header:</span>
                      {hop.rawHeader}
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* Trace Details Accordion */}
      <h2 className="flex items-center gap-2.5 text-lg font-extrabold tracking-[0.2px] mb-4 text-[#f2f6fc]">
        <span className="w-2 h-2 rounded-full bg-[#3fd0f0] shadow-[0_0_10px_#3fd0f0]"></span>
        Original Received Headers Chain
      </h2>

      <details className="bg-[#121b2b] border border-[#202e45] rounded-[14px] overflow-hidden mb-8 group" open>
        <summary className="list-none cursor-pointer p-5 font-extrabold text-sm md:text-base flex items-center justify-between text-[#f2f6fc] select-none hover:bg-white/[0.02] transition-colors">
          <div className="flex items-center gap-2.5">
            <Route className="w-4 h-4 text-[#3fd0f0]" />
            Raw RFC 822 Received Headers (Newest to Oldest)
          </div>
          <ChevronDown className="w-4 h-4 text-[#aab9d0] transition-transform duration-200 group-open:rotate-180" />
        </summary>
        <div className="bg-[#0a101c] border-t border-[#202e45] p-5 font-mono text-xs text-[#bfd2e8] leading-loose whitespace-pre-wrap break-all">
          {analysisCase.technicalDetails.receivedChain.length > 0 ? (
            analysisCase.technicalDetails.receivedChain.map((line, idx) => (
              <div key={idx} className="mb-3 pb-3 border-b border-[#1b263a] last:border-b-0">
                <span className="text-[#8fe8ff] font-bold">[Header {idx + 1}]</span>
                <br />
                {line}
              </div>
            ))
          ) : (
            <div>No Received headers present in submitted email.</div>
          )}
        </div>
      </details>

      {/* Navigation Buttons */}
      <section className="flex flex-wrap items-center justify-between gap-3 p-6 rounded-[14px] border border-dashed border-[#31445f] bg-[#182339]">
        <button
          onClick={() => onNavigate('results')}
          className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-bold bg-transparent border border-[#31445f] text-[#d8e2f0] hover:border-[#3fd0f0] hover:text-[#3fd0f0] transition-all cursor-pointer"
        >
          ← Back to Results
        </button>
        <div className="flex gap-2.5">
          <button
            onClick={() => onNavigate('graph')}
            className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-bold bg-gradient-to-b from-[#2ec9ec] to-[#17a7d8] text-[#06131c] shadow-[0_4px_18px_rgba(23,167,216,0.35)] hover:brightness-110 transition-all cursor-pointer"
          >
            Investigation Graph →
          </button>
          <button
            onClick={() => onNavigate('report')}
            className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-bold bg-transparent border border-[#31445f] text-[#d8e2f0] hover:border-[#3fd0f0] hover:text-[#3fd0f0] transition-all cursor-pointer"
          >
            Forensic Report
          </button>
        </div>
      </section>
    </div>
  );
};
