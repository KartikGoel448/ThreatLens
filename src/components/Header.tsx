import React from 'react';
import { ShieldAlert, Plus, History, Sparkles, CheckCircle2 } from 'lucide-react';
import type { EmailAnalysisCase } from '../types';

interface HeaderProps {
  currentView: 'analyzer' | 'results' | 'trace' | 'graph' | 'report' | 'about';
  onNavigate: (view: 'analyzer' | 'results' | 'trace' | 'graph' | 'report' | 'about') => void;
  currentCase: EmailAnalysisCase | null;
  cases: Array<{ caseId: string; subject: string; riskScore: number; verdict: string }>;
  onSelectCase: (caseId: string) => void;
  onNewAnalysis: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  currentView,
  onNavigate,
  currentCase,
  cases,
  onSelectCase,
  onNewAnalysis,
}) => {
  const [showHistory, setShowHistory] = React.useState(false);

  return (
    <header className="sticky top-0 z-50 flex items-center justify-between h-[66px] px-4 md:px-8 bg-[#0a0e17]/95 backdrop-blur-md border-b border-[#202e45] no-print">
      <div className="flex items-center gap-3">
        <button
          onClick={() => onNavigate('analyzer')}
          className="flex items-center gap-3 text-left group focus:outline-none cursor-pointer"
        >
          <div className="w-[34px] height-[34px] h-[34px] rounded-[9px] bg-gradient-to-b from-[#2ec9ec] to-[#17a7d8] grid place-items-center text-[#06131c] shadow-[0_0_18px_rgba(63,208,240,0.35)] shrink-0 transition-transform group-hover:scale-105">
            <ShieldAlert className="w-5 h-5 stroke-[2.2]" />
          </div>
          <div>
            <div className="text-[17px] font-extrabold tracking-[0.2px] text-[#f2f6fc] leading-tight">
              ThreatLens
            </div>
            <div className="text-[9.8px] font-bold text-[#9db2ce] tracking-[1.1px] uppercase">
              AI-Powered Email Threat Analysis
            </div>
          </div>
        </button>

        <nav className="hidden lg:flex items-center gap-1 ml-6">
          <button
            onClick={() => onNavigate('analyzer')}
            className={`px-3 py-1.5 rounded-lg text-sm font-semibold transition-colors cursor-pointer ${
              currentView === 'analyzer'
                ? 'text-[#3fd0f0] bg-[#0e2733] ring-1 ring-[#1f5a72]'
                : 'text-[#d8e2f0] hover:text-[#f2f6fc] hover:bg-white/5'
            }`}
          >
            Dashboard
          </button>
          <button
            onClick={() => onNavigate('results')}
            className={`px-3 py-1.5 rounded-lg text-sm font-semibold transition-colors cursor-pointer ${
              currentView === 'results'
                ? 'text-[#3fd0f0] bg-[#0e2733] ring-1 ring-[#1f5a72]'
                : 'text-[#d8e2f0] hover:text-[#f2f6fc] hover:bg-white/5'
            }`}
          >
            Analyses
          </button>
          <button
            onClick={() => onNavigate('trace')}
            className={`px-3 py-1.5 rounded-lg text-sm font-semibold transition-colors cursor-pointer ${
              currentView === 'trace'
                ? 'text-[#3fd0f0] bg-[#0e2733] ring-1 ring-[#1f5a72]'
                : 'text-[#d8e2f0] hover:text-[#f2f6fc] hover:bg-white/5'
            }`}
          >
            Investigation
          </button>
          <button
            onClick={() => onNavigate('graph')}
            className={`px-3 py-1.5 rounded-lg text-sm font-semibold transition-colors cursor-pointer ${
              currentView === 'graph'
                ? 'text-[#3fd0f0] bg-[#0e2733] ring-1 ring-[#1f5a72]'
                : 'text-[#d8e2f0] hover:text-[#f2f6fc] hover:bg-white/5'
            }`}
          >
            Graph
          </button>
          <button
            onClick={() => onNavigate('report')}
            className={`px-3 py-1.5 rounded-lg text-sm font-semibold transition-colors cursor-pointer ${
              currentView === 'report'
                ? 'text-[#3fd0f0] bg-[#0e2733] ring-1 ring-[#1f5a72]'
                : 'text-[#d8e2f0] hover:text-[#f2f6fc] hover:bg-white/5'
            }`}
          >
            Reports
          </button>
          <button
            onClick={() => onNavigate('about')}
            className={`px-3 py-1.5 rounded-lg text-sm font-semibold transition-colors cursor-pointer ${
              currentView === 'about'
                ? 'text-[#3fd0f0] bg-[#0e2733] ring-1 ring-[#1f5a72]'
                : 'text-[#d8e2f0] hover:text-[#f2f6fc] hover:bg-white/5'
            }`}
          >
            About
          </button>
        </nav>
      </div>

      <div className="flex items-center gap-3">
        {currentCase && (
          <div className="hidden sm:inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-[#0e2733] border border-[#1f5a72] text-[11px] font-mono text-[#6fe1ff]">
            <span className="w-1.5 h-1.5 rounded-full bg-[#3fd0f0] animate-pulse"></span>
            {currentCase.caseId}
          </div>
        )}

        <div className="relative">
          <button
            onClick={() => setShowHistory(!showHistory)}
            title="Recent Cases"
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-semibold text-[#d8e2f0] bg-[#121b2b] border border-[#202e45] hover:border-[#3fd0f0] hover:text-[#3fd0f0] transition-colors cursor-pointer"
          >
            <History className="w-3.5 h-3.5" />
            <span className="hidden md:inline">History ({cases.length})</span>
          </button>

          {showHistory && (
            <div className="absolute right-0 mt-2 w-72 md:w-80 rounded-xl bg-[#121b2b] border border-[#31445f] shadow-2xl p-2 z-50">
              <div className="text-xs font-bold uppercase tracking-wider text-[#aab9d0] px-3 py-1.5 border-b border-[#202e45] mb-1">
                Recent Threat Cases
              </div>
              <div className="max-h-60 overflow-y-auto space-y-1">
                {cases.map((c) => (
                  <button
                    key={c.caseId}
                    onClick={() => {
                      onSelectCase(c.caseId);
                      setShowHistory(false);
                    }}
                    className={`w-full text-left px-3 py-2 rounded-lg text-xs transition-colors flex items-center justify-between cursor-pointer ${
                      currentCase?.caseId === c.caseId
                        ? 'bg-[#182339] border border-[#1f5a72] text-[#3fd0f0]'
                        : 'hover:bg-[#182339] text-[#d8e2f0]'
                    }`}
                  >
                    <div className="truncate pr-2">
                      <div className="font-mono font-bold">{c.caseId}</div>
                      <div className="truncate text-[#aab9d0] text-[11px]">{c.subject}</div>
                    </div>
                    <span
                      className={`px-1.5 py-0.5 rounded text-[10px] font-extrabold shrink-0 ${
                        c.riskScore >= 65
                          ? 'bg-[#301419] text-[#ff5d63] border border-[#8f2f37]'
                          : c.riskScore >= 35
                          ? 'bg-[#2c2110] text-[#ffb92e] border border-[#8a641f]'
                          : 'bg-[#122b20] text-[#38d98c] border border-[#267a52]'
                      }`}
                    >
                      {c.riskScore}
                    </span>
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>

        <button
          onClick={onNewAnalysis}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs md:text-sm font-bold bg-transparent border border-[#31445f] text-[#d8e2f0] hover:border-[#3fd0f0] hover:text-[#3fd0f0] transition-colors cursor-pointer"
        >
          <Plus className="w-4 h-4" />
          <span className="hidden sm:inline">New Analysis</span>
        </button>

        <div className="hidden sm:flex items-center gap-1 text-[11px] font-bold text-[#ffb92e] bg-[#2c2110] border border-[#8a641f] px-2.5 py-1 rounded-full uppercase tracking-wider">
          <Sparkles className="w-3 h-3" />
          Threat Engine
        </div>

        <div
          title="Senior Security Analyst (SA)"
          className="w-8 h-8 rounded-full bg-[#1e2c45] border border-[#31445f] grid place-items-center text-[#d8e2f0] font-extrabold text-xs shrink-0 select-none shadow-sm"
        >
          SA
        </div>
      </div>
    </header>
  );
};
