import React from 'react';

interface BreadcrumbsProps {
  currentView: 'analyzer' | 'results' | 'trace' | 'graph' | 'report' | 'about';
  onNavigate: (view: 'analyzer' | 'results' | 'trace' | 'graph' | 'report' | 'about') => void;
}

export const Breadcrumbs: React.FC<BreadcrumbsProps> = ({ currentView, onNavigate }) => {
  return (
    <div className="flex items-center gap-2.5 text-[13px] my-4 flex-wrap text-[#aab9d0] no-print">
      <button
        onClick={() => onNavigate('analyzer')}
        className={`font-semibold cursor-pointer transition-colors ${
          currentView === 'analyzer' ? 'text-[#3fd0f0]' : 'hover:text-[#f2f6fc]'
        }`}
      >
        Analyze
      </button>
      <span className="text-[#31445f]">›</span>
      <button
        onClick={() => onNavigate('results')}
        className={`font-semibold cursor-pointer transition-colors ${
          currentView === 'results' ? 'text-[#3fd0f0]' : 'hover:text-[#f2f6fc]'
        }`}
      >
        Threat Results
      </button>
      <span className="text-[#31445f]">›</span>
      <button
        onClick={() => onNavigate('trace')}
        className={`font-semibold cursor-pointer transition-colors ${
          currentView === 'trace' ? 'text-[#3fd0f0]' : 'hover:text-[#f2f6fc]'
        }`}
      >
        Relay Trace
      </button>
      <span className="text-[#31445f]">›</span>
      <button
        onClick={() => onNavigate('graph')}
        className={`font-semibold cursor-pointer transition-colors ${
          currentView === 'graph' ? 'text-[#3fd0f0]' : 'hover:text-[#f2f6fc]'
        }`}
      >
        Investigation Graph
      </button>
      <span className="text-[#31445f]">›</span>
      <button
        onClick={() => onNavigate('report')}
        className={`font-semibold cursor-pointer transition-colors ${
          currentView === 'report' ? 'text-[#3fd0f0]' : 'hover:text-[#f2f6fc]'
        }`}
      >
        Forensic Report
      </button>
    </div>
  );
};
