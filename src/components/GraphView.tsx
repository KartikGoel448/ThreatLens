import React, { useState } from 'react';
import {
  Network,
  Globe,
  Server,
  Mail,
  Link,
  ShieldAlert,
  Info,
  ExternalLink,
  CheckCircle2,
  AlertTriangle,
  Layers,
} from 'lucide-react';
import type { EmailAnalysisCase, GraphEntity } from '../types';

interface GraphViewProps {
  analysisCase: EmailAnalysisCase;
  onNavigate: (view: 'analyzer' | 'results' | 'trace' | 'graph' | 'report' | 'about') => void;
  onShowToast: (msg: string) => void;
}

export const GraphView: React.FC<GraphViewProps> = ({
  analysisCase,
  onNavigate,
  onShowToast,
}) => {
  const entities = analysisCase.graph?.entities || {};
  const edges = analysisCase.graph?.edges || [];

  const [selectedKey, setSelectedKey] = useState<string>(
    analysisCase.graph?.activeEntityKey || Object.keys(entities)[0] || 'email'
  );

  const activeEntity: GraphEntity | undefined = entities[selectedKey] || Object.values(entities)[0];

  const handleNodeClick = (key: string) => {
    setSelectedKey(key);
    const ent = entities[key];
    if (ent) {
      onShowToast(`Selected ${ent.type}: ${ent.value}`);
    }
  };

  const correlation = analysisCase.correlation;
  const isCampaignDetected = correlation?.campaignCandidate?.detected;
  const totalAnalyzed = correlation?.totalAnalyzedCasesCount ?? 1;

  return (
    <div className="w-full max-w-[1240px] mx-auto py-2">
      {/* Hero Section */}
      <section className="text-center mb-6">
        <div className="text-xs font-mono font-bold text-[#3fd0f0] uppercase tracking-wider mb-2">
          Case {analysisCase.caseId} · Infrastructure Graph &amp; Campaign Correlation
        </div>
        <h1 className="text-2xl md:text-4xl font-extrabold tracking-[-0.5px] text-[#f2f6fc]">
          Investigation Graph
        </h1>
        <p className="text-sm md:text-base text-[#d8e2f0] mt-2 max-w-xl mx-auto">
          Multi-dimensional correlation linking sender domains, relay IPs, URL hosts, and related cases.
        </p>
      </section>

      {/* Campaign Candidate Status Banner (Step 5 Requirement) */}
      {isCampaignDetected && correlation?.campaignCandidate ? (
        <section className="bg-[#1f1635] border-2 border-[#a855f7]/70 rounded-[14px] p-5 mb-6 shadow-[0_8px_30px_rgba(168,85,247,0.2)]">
          <div className="flex items-start justify-between gap-4 flex-wrap">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-[#3b1d6e] border border-[#a855f7] flex items-center justify-center text-[#d8b4fe] shrink-0">
                <Network className="w-5 h-5" />
              </div>
              <div>
                <div className="flex items-center gap-2.5 flex-wrap">
                  <h2 className="text-base md:text-lg font-extrabold text-[#f3e8ff]">
                    Campaign Candidate — shared infrastructure detected
                  </h2>
                  <span className="text-xs font-mono font-bold px-2.5 py-0.5 rounded-full bg-[#3b1d6e] border border-[#a855f7] text-[#e9d5ff]">
                    {correlation.campaignCandidate.confidenceScore}% Confidence
                  </span>
                </div>
                <p className="text-xs md:text-sm text-[#d8b4fe]/90 mt-1 max-w-3xl leading-relaxed">
                  {correlation.campaignCandidate.disclaimer ||
                    'This correlation indicates shared observable infrastructure across analyzed cases. It does not prove common ownership or attacker attribution.'}
                </p>
              </div>
            </div>
          </div>

          {/* Shared Infrastructure Items */}
          <div className="mt-4 pt-3.5 border-t border-[#3b1d6e] flex flex-wrap gap-2 items-center">
            <span className="text-xs font-semibold text-[#c084fc]">Shared Infrastructure:</span>
            {correlation.campaignCandidate.sharedEntities.map((se, idx) => (
              <span
                key={idx}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-mono font-bold bg-[#2e1065] border border-[#9333ea] text-[#f3e8ff]"
              >
                <span className="text-[#c084fc] font-sans font-semibold">{se.type}:</span>
                {se.value}
              </span>
            ))}
          </div>

          {/* Evidence Explanation List */}
          {correlation.campaignCandidate.evidence.length > 0 && (
            <div className="mt-3 space-y-1.5">
              {correlation.campaignCandidate.evidence.map((ev, i) => (
                <div key={i} className="text-xs text-[#e9d5ff]/90 flex items-start gap-2">
                  <span className="w-1.5 h-1.5 rounded-full bg-[#c084fc] mt-1.5 shrink-0"></span>
                  <span>{ev}</span>
                </div>
              ))}
            </div>
          )}
        </section>
      ) : totalAnalyzed <= 1 ? (
        <section className="bg-[#121b2b] border border-[#202e45] rounded-[14px] p-4 mb-6 flex items-center gap-3.5 text-xs md:text-sm shadow-[0_4px_16px_rgba(0,0,0,0.2)]">
          <Info className="w-5 h-5 text-[#3fd0f0] shrink-0" />
          <div>
            <span className="font-bold text-[#d8e2f0] block">
              Campaign correlation requires comparable analyzed cases.
            </span>
            <span className="text-[#8fa7c4] text-xs block mt-0.5">
              Analyze additional emails in ThreatLens to automatically identify recurring sender domains, relay hops, or credential-harvesting destinations across cases.
            </span>
          </div>
        </section>
      ) : (
        <section className="bg-[#121b2b] border border-[#202e45] rounded-[14px] p-4 mb-6 flex items-center gap-3.5 text-xs md:text-sm shadow-[0_4px_16px_rgba(0,0,0,0.2)]">
          <CheckCircle2 className="w-5 h-5 text-[#38d98c] shrink-0" />
          <div>
            <span className="font-bold text-[#d8e2f0] block">
              No meaningful shared infrastructure detected.
            </span>
            <span className="text-[#8fa7c4] text-xs block mt-0.5">
              Observable indicators (sender domains, public relay IPs, URL hosts) do not overlap with infrastructure from {totalAnalyzed} stored cases.
            </span>
          </div>
        </section>
      )}

      {/* Interactive Graph Layout: Graph SVG (Left) + Entity Inspector (Right) */}
      <section className="grid grid-cols-1 lg:grid-cols-[1fr_340px] gap-6 items-start mb-8">
        {/* SVG Graph Box */}
        <div className="bg-[#0b1120] border border-[#202e45] rounded-[14px] overflow-hidden shadow-[0_12px_34px_rgba(0,0,0,0.38)]">
          <div className="relative p-2">
            <svg
              className="w-full h-auto block select-none"
              viewBox="0 0 880 580"
            >
              <defs>
                <radialGradient id="graphGlow" cx="50%" cy="40%" r="60%">
                  <stop offset="0%" stopColor="#3fd0f0" stopOpacity="0.08" />
                  <stop offset="100%" stopColor="#3fd0f0" stopOpacity="0" />
                </radialGradient>
                <filter id="nodeShadow" x="-20%" y="-20%" width="140%" height="140%">
                  <feDropShadow dx="0" dy="0" stdDeviation="6" floodColor="#3fd0f0" floodOpacity="0.5" />
                </filter>
              </defs>

              {/* Background gradient */}
              <rect width="880" height="580" fill="url(#graphGlow)" />

              {/* Edges */}
              <g>
                {edges.map((edge, i) => {
                  const fromNode = entities[edge.from];
                  const toNode = entities[edge.to];
                  if (!fromNode || !toNode) return null;

                  const x1 = fromNode.x || 430;
                  const y1 = fromNode.y || 300;
                  const x2 = toNode.x || 430;
                  const y2 = toNode.y || 300;

                  const isHot = edge.hot;
                  const isDashed = edge.dashed;
                  const isConnectedToSelected =
                    edge.from === selectedKey || edge.to === selectedKey;

                  return (
                    <line
                      key={i}
                      x1={x1}
                      y1={y1}
                      x2={x2}
                      y2={y2}
                      stroke={
                        isConnectedToSelected
                          ? '#3fd0f0'
                          : isHot
                          ? '#ff5d63'
                          : '#2c405e'
                      }
                      strokeWidth={isConnectedToSelected ? 2.5 : isHot ? 2 : 1.6}
                      strokeDasharray={isDashed ? '5 5' : undefined}
                      strokeOpacity={isConnectedToSelected ? 0.95 : isHot ? 0.85 : 0.6}
                      className="transition-all duration-300"
                    />
                  );
                })}
              </g>

              {/* Entity Nodes */}
              {(Object.entries(entities) as [string, GraphEntity][]).map(([key, node]) => {
                const isSelected = selectedKey === key;
                const x = node.x || 430;
                const y = node.y || 300;
                const isCampaign = node.type === 'Campaign Candidate';
                const isCurrent = node.isCurrentCase;

                return (
                  <g
                    key={key}
                    transform={`translate(${x} ${y})`}
                    onClick={() => handleNodeClick(key)}
                    className="cursor-pointer group"
                    filter={isSelected ? 'url(#nodeShadow)' : undefined}
                  >
                    {/* Node card box */}
                    <rect
                      x="-108"
                      y="-28"
                      width="216"
                      height="56"
                      rx="10"
                      fill={isCampaign ? '#1f1635' : isCurrent ? '#16243d' : '#152036'}
                      stroke={
                        isSelected
                          ? '#3fd0f0'
                          : isCampaign
                          ? '#a855f7'
                          : isCurrent
                          ? '#2ec9ec'
                          : '#2b3d5c'
                      }
                      strokeWidth={isSelected ? 2.4 : isCampaign || isCurrent ? 1.8 : 1.4}
                      className="transition-all duration-200 group-hover:stroke-[#3fd0f0]"
                    />

                    {/* Left category icon bubble */}
                    <circle
                      cx="-76"
                      cy="0"
                      r="16"
                      fill={
                        isCampaign
                          ? '#2e1065'
                          : node.type === 'Email'
                          ? '#0e2733'
                          : node.type === 'Domain'
                          ? '#2c2110'
                          : node.type === 'IP Address'
                          ? '#301419'
                          : '#122b20'
                      }
                      stroke={
                        isCampaign
                          ? '#9333ea'
                          : node.type === 'Email'
                          ? '#1f5a72'
                          : node.type === 'Domain'
                          ? '#8a641f'
                          : node.type === 'IP Address'
                          ? '#8f2f37'
                          : '#267a52'
                      }
                      strokeWidth="1.2"
                    />

                    {/* Mini Icon inside circle */}
                    <g transform="translate(-76, 0)">
                      {isCampaign ? (
                        <circle r="5" fill="#c084fc" />
                      ) : node.type === 'Email' ? (
                        <path
                          d="M -7 -5 L 7 -5 L 7 5 L -7 5 Z M -7 -5 L 0 0 L 7 -5"
                          fill="none"
                          stroke="#3fd0f0"
                          strokeWidth="1.5"
                        />
                      ) : node.type === 'Domain' ? (
                        <circle
                          r="6"
                          fill="none"
                          stroke="#ffb92e"
                          strokeWidth="1.5"
                        />
                      ) : node.type === 'IP Address' ? (
                        <rect
                          x="-6"
                          y="-5"
                          width="12"
                          height="10"
                          rx="1"
                          fill="none"
                          stroke="#ff5d63"
                          strokeWidth="1.5"
                        />
                      ) : (
                        <path
                          d="M -5 -2 L -1 -2 A 3 3 0 0 1 -1 4 L -5 4 M 5 2 L 1 2 A 3 3 0 0 1 1 -4 L 5 -4"
                          fill="none"
                          stroke="#38d98c"
                          strokeWidth="1.5"
                        />
                      )}
                    </g>

                    {/* Labels */}
                    <text
                      x="-52"
                      y="-4"
                      fill={isCampaign ? '#f3e8ff' : '#dbe7f5'}
                      fontSize="12.5"
                      fontWeight="700"
                      fontFamily="-apple-system, BlinkMacSystemFont, Segoe UI, sans-serif"
                    >
                      {isCampaign
                        ? 'Campaign Cluster'
                        : isCurrent && node.type === 'Email'
                        ? 'Current Email'
                        : node.type === 'Email'
                        ? 'Correlated Case'
                        : node.type === 'Domain'
                        ? 'Sender Domain'
                        : node.type === 'IP Address'
                        ? 'Relay Host IP'
                        : 'Flagged URL'}
                    </text>
                    <text
                      x="-52"
                      y="11"
                      fill={isCampaign ? '#c084fc' : '#8fa7c4'}
                      fontSize="10.8"
                      fontFamily="SF Mono, Consolas, monospace"
                    >
                      {node.value.length > 20 ? node.value.slice(0, 18) + '...' : node.value}
                    </text>
                  </g>
                );
              })}
            </svg>
          </div>

          {/* Graph Legend */}
          <div className="flex flex-wrap items-center gap-x-5 gap-y-2 p-4 border-t border-[#202e45] bg-[#121b2b] text-xs text-[#d8e2f0]">
            <span className="flex items-center gap-2">
              <i className="w-2.5 h-2.5 rounded-sm bg-[#3fd0f0]"></i>
              Email / Case
            </span>
            <span className="flex items-center gap-2">
              <i className="w-2.5 h-2.5 rounded-sm bg-[#ffb92e]"></i>
              Domain
            </span>
            <span className="flex items-center gap-2">
              <i className="w-2.5 h-2.5 rounded-sm bg-[#ff5d63]"></i>
              IP Address
            </span>
            <span className="flex items-center gap-2">
              <i className="w-2.5 h-2.5 rounded-sm bg-[#38d98c]"></i>
              URL
            </span>
            {isCampaignDetected && (
              <span className="flex items-center gap-2">
                <i className="w-2.5 h-2.5 rounded-sm bg-[#a855f7]"></i>
                Campaign Cluster
              </span>
            )}
            <span className="ml-auto text-[11px] text-[#aab9d0]">
              Click any node to inspect evidence
            </span>
          </div>
        </div>

        {/* Entity Inspector Sidebar */}
        <div className="bg-[#121b2b] border border-[#202e45] rounded-[14px] p-6 shadow-[0_12px_34px_rgba(0,0,0,0.38)]">
          <div className="flex items-center gap-2 text-base font-extrabold text-[#f2f6fc] mb-4">
            <Info className="w-4 h-4 text-[#3fd0f0]" />
            Entity Details
          </div>

          {activeEntity && (
            <div>
              <dl className="divide-y divide-[#202e45]">
                <div className="flex justify-between py-2.5 text-sm">
                  <dt className="text-[#aab9d0] font-semibold">Entity Type</dt>
                  <dd className="font-bold text-[#3fd0f0]">{activeEntity.type}</dd>
                </div>

                <div className="flex justify-between py-2.5 text-sm">
                  <dt className="text-[#aab9d0] font-semibold">Value</dt>
                  <dd className="font-mono text-[#f2f6fc] text-xs break-all max-w-[190px] text-right">
                    {activeEntity.value}
                  </dd>
                </div>

                {activeEntity.relationship && (
                  <div className="flex justify-between py-2.5 text-sm">
                    <dt className="text-[#aab9d0] font-semibold">Relationship</dt>
                    <dd className="font-semibold text-xs text-[#dbe7f5] text-right max-w-[180px]">
                      {activeEntity.relationship}
                    </dd>
                  </div>
                )}

                <div className="flex justify-between py-2.5 text-sm">
                  <dt className="text-[#aab9d0] font-semibold">Risk</dt>
                  <dd>
                    <span
                      className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold uppercase border ${
                        activeEntity.cls === 'fail'
                          ? 'text-[#ff7d82] bg-[#301419] border-[#8f2f37]'
                          : activeEntity.cls === 'warn'
                          ? 'text-[#ffc45c] bg-[#2c2110] border-[#8a641f]'
                          : 'text-[#4fe0a0] bg-[#122b20] border-[#267a52]'
                      }`}
                    >
                      {activeEntity.risk}
                    </span>
                  </dd>
                </div>

                <div className="flex justify-between py-2.5 text-sm">
                  <dt className="text-[#aab9d0] font-semibold">First Seen</dt>
                  <dd className="text-[#f2f6fc] font-semibold text-xs md:text-sm">
                    {activeEntity.firstSeen}
                  </dd>
                </div>

                {activeEntity.observedCases && activeEntity.observedCases.length > 0 && (
                  <div className="py-2.5 text-sm">
                    <dt className="text-[#aab9d0] font-semibold mb-1">Observed in Cases</dt>
                    <dd className="flex flex-wrap gap-1.5">
                      {activeEntity.observedCases.map((cid, i) => (
                        <span
                          key={i}
                          className="font-mono text-[11px] font-bold px-2 py-0.5 rounded bg-[#182339] border border-[#31445f] text-[#3fd0f0]"
                        >
                          {cid}
                        </span>
                      ))}
                    </dd>
                  </div>
                )}

                {activeEntity.sharedEvidenceExplanation && (
                  <div className="py-2.5 text-sm">
                    <dt className="text-[#aab9d0] font-semibold mb-1">Evidence</dt>
                    <dd className="text-xs text-[#d8e2f0] leading-relaxed bg-[#0b1120] p-2.5 rounded-lg border border-[#202e45]">
                      {activeEntity.sharedEvidenceExplanation}
                    </dd>
                  </div>
                )}

                <div className="flex justify-between py-2.5 text-sm">
                  <dt className="text-[#aab9d0] font-semibold">Linked Entities</dt>
                  <dd className="font-extrabold text-[#f2f6fc]">{activeEntity.count}</dd>
                </div>
              </dl>

              {/* Related Entities list */}
              <div className="mt-5 pt-4 border-t border-[#202e45]">
                <div className="font-extrabold text-xs text-[#aab9d0] tracking-wider uppercase mb-3">
                  Connected Indicators ({activeEntity.related.length})
                </div>
                <div className="flex flex-col gap-2">
                  {activeEntity.related.map((r, idx) => {
                    const isIp = r.includes('IP');
                    const isDomainOrUrl = r.includes('Domain') || r.includes('URL');

                    return (
                      <span
                        key={idx}
                        className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border truncate ${
                          isIp
                            ? 'text-[#ffe2e3] bg-[#ff5d63]/10 border-[#ff5d63]/30'
                            : isDomainOrUrl
                            ? 'text-[#fff4dc] bg-[#ffb92e]/10 border-[#ffb92e]/30'
                            : 'text-[#cfeefb] bg-[#3fd0f0]/10 border-[#3fd0f0]/30'
                        }`}
                      >
                        {r}
                      </span>
                    );
                  })}
                </div>
              </div>
            </div>
          )}
        </div>
      </section>

      {/* Navigation Buttons */}
      <section className="flex flex-wrap items-center justify-between gap-3 p-6 rounded-[14px] border border-dashed border-[#31445f] bg-[#182339]">
        <div className="flex gap-2.5">
          <button
            onClick={() => onNavigate('trace')}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-bold bg-transparent border border-[#31445f] text-[#d8e2f0] hover:border-[#3fd0f0] hover:text-[#3fd0f0] transition-all cursor-pointer"
          >
            ← Relay Trace
          </button>
          <button
            onClick={() => onNavigate('results')}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-bold bg-transparent border border-[#31445f] text-[#d8e2f0] hover:border-[#3fd0f0] hover:text-[#3fd0f0] transition-all cursor-pointer"
          >
            Results
          </button>
        </div>
        <button
          onClick={() => onNavigate('report')}
          className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-bold bg-gradient-to-b from-[#2ec9ec] to-[#17a7d8] text-[#06131c] shadow-[0_4px_18px_rgba(23,167,216,0.35)] hover:brightness-110 transition-all cursor-pointer"
        >
          Forensic Report →
        </button>
      </section>
    </div>
  );
};
