import React, { useState, useEffect } from 'react';
import { Header } from './components/Header';
import { Breadcrumbs } from './components/Breadcrumbs';
import { AnalyzerView } from './components/AnalyzerView';
import { ResultsView } from './components/ResultsView';
import { TraceView } from './components/TraceView';
import { GraphView } from './components/GraphView';
import { ReportView } from './components/ReportView';
import { AboutView } from './components/AboutView';
import { Toast } from './components/Toast';
import type { EmailAnalysisCase, SampleEmailPreset } from './types';

export default function App() {
  const [currentView, setCurrentView] = useState<
    'analyzer' | 'results' | 'trace' | 'graph' | 'report' | 'about'
  >('analyzer');

  const [currentCase, setCurrentCase] = useState<EmailAnalysisCase | null>(null);
  const [casesList, setCasesList] = useState<
    Array<{ caseId: string; subject: string; riskScore: number; verdict: string }>
  >([]);
  const [presets, setPresets] = useState<SampleEmailPreset[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => {
      setToastMessage((prev) => (prev === msg ? null : prev));
    }, 2800);
  };

  // Fetch initial samples and pre-seeded cases
  useEffect(() => {
    async function loadInit() {
      try {
        const [samplesRes, casesRes] = await Promise.all([
          fetch('/api/samples').catch(() => null),
          fetch('/api/analyses').catch(() => null),
        ]);

        if (samplesRes && samplesRes.ok) {
          const sData = await samplesRes.json();
          if (sData.samples) {
            setPresets(sData.samples);
          }
        }

        if (casesRes && casesRes.ok) {
          const cData = await casesRes.json();
          if (cData.cases && cData.cases.length > 0) {
            setCasesList(cData.cases);
            // Preload the default case
            const firstId = cData.cases[0].caseId;
            const singleRes = await fetch(`/api/analyses/${firstId}`).catch(() => null);
            if (singleRes && singleRes.ok) {
              const singleData = await singleRes.json();
              if (singleData.case) {
                setCurrentCase(singleData.case);
              }
            }
          }
        }
      } catch (err) {
        console.error('Failed to load initial data:', err);
      }
    }

    loadInit();
  }, []);

  // Handle Analyze request
  const handleAnalyze = async (rawContent: string) => {
    setIsLoading(true);
    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rawText: rawContent }),
      });

      if (!response.ok) {
        const errJson = await response.json().catch(() => ({}));
        throw new Error(errJson.error || 'Server error during threat analysis');
      }

      const data = await response.json();
      if (data.case) {
        setCurrentCase(data.case);
        setCasesList((prev) => [
          {
            caseId: data.case.caseId,
            subject: data.case.subject,
            riskScore: data.case.riskScore,
            verdict: data.case.verdict,
          },
          ...prev.filter((c) => c.caseId !== data.case.caseId),
        ]);
        setCurrentView('results');
        showToast(`Analysis complete: Case ${data.case.caseId} generated.`);
      }
    } catch (err: any) {
      console.error(err);
      showToast(err.message || 'Error occurred during analysis');
    } finally {
      setIsLoading(false);
    }
  };

  // Handle selecting past case
  const handleSelectCase = async (caseId: string) => {
    try {
      const res = await fetch(`/api/analyses/${caseId}`);
      if (res.ok) {
        const data = await res.json();
        if (data.case) {
          setCurrentCase(data.case);
          setCurrentView('results');
          showToast(`Loaded Case ${caseId}`);
        }
      }
    } catch (err) {
      console.error(err);
      showToast(`Failed to load case ${caseId}`);
    }
  };

  return (
    <div className="min-h-screen flex flex-col bg-[#0a0e17] text-[#f2f6fc]">
      {/* Top Header Bar */}
      <Header
        currentView={currentView}
        onNavigate={setCurrentView}
        currentCase={currentCase}
        cases={casesList}
        onSelectCase={handleSelectCase}
        onNewAnalysis={() => setCurrentView('analyzer')}
      />

      {/* Main Container */}
      <main className="flex-1 max-w-[1240px] w-full mx-auto px-4 md:px-8 py-6">
        {/* Breadcrumb Navigation when viewing results/trace/graph/report */}
        {currentView !== 'about' && (
          <Breadcrumbs currentView={currentView} onNavigate={setCurrentView} />
        )}

        {/* View Switcher */}
        {currentView === 'analyzer' && (
          <AnalyzerView
            onAnalyze={handleAnalyze}
            isLoading={isLoading}
            presets={presets}
          />
        )}

        {currentView === 'results' && (
          currentCase ? (
            <ResultsView
              analysisCase={currentCase}
              onNavigate={setCurrentView}
              onShowToast={showToast}
            />
          ) : (
            <AnalyzerView
              onAnalyze={handleAnalyze}
              isLoading={isLoading}
              presets={presets}
            />
          )
        )}

        {currentView === 'trace' && (
          currentCase ? (
            <TraceView
              analysisCase={currentCase}
              onNavigate={setCurrentView}
            />
          ) : (
            <AnalyzerView
              onAnalyze={handleAnalyze}
              isLoading={isLoading}
              presets={presets}
            />
          )
        )}

        {currentView === 'graph' && (
          currentCase ? (
            <GraphView
              analysisCase={currentCase}
              onNavigate={setCurrentView}
              onShowToast={showToast}
            />
          ) : (
            <AnalyzerView
              onAnalyze={handleAnalyze}
              isLoading={isLoading}
              presets={presets}
            />
          )
        )}

        {currentView === 'report' && (
          currentCase ? (
            <ReportView
              analysisCase={currentCase}
              onNavigate={setCurrentView}
              onShowToast={showToast}
            />
          ) : (
            <AnalyzerView
              onAnalyze={handleAnalyze}
              isLoading={isLoading}
              presets={presets}
            />
          )
        )}

        {currentView === 'about' && (
          <AboutView onNavigate={setCurrentView} />
        )}
      </main>

      {/* Global Toast */}
      <Toast message={toastMessage} />

      {/* Footer */}
      <footer className="border-t border-[#202e45] py-6 px-6 text-center text-xs text-[#aab9d0] leading-relaxed no-print">
        <div>
          ThreatLens — AI-Powered Email Threat Analysis
          {currentCase && ` · Case ${currentCase.caseId}`}
        </div>
        <div className="mt-1">
          Full-Stack Threat Intelligence Engine · © 2026 ThreatLens Labs
        </div>
      </footer>
    </div>
  );
}
