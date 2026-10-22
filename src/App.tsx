import { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { VulnerabilityExplorer } from './components/VulnerabilityExplorer';
import { VersionMatrixView } from './components/VersionMatrixView';
import { ChallengeArena } from './components/ChallengeArena';
import { HardeningAuditor } from './components/HardeningAuditor';
import { PayloadToolsView } from './components/PayloadToolsView';
import { CTF_CHALLENGES } from './data/challenges';
import { Shield, BookOpen, Terminal, Cpu, Wrench } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState<'explorer' | 'matrix' | 'challenges' | 'hardening' | 'tools'>('explorer');
  const [solvedChallenges, setSolvedChallenges] = useState<string[]>(() => {
    try {
      const saved = localStorage.getItem('php_vulnlab_solved');
      return saved ? JSON.parse(saved) : [];
    } catch {
      return [];
    }
  });

  useEffect(() => {
    try {
      localStorage.setItem('php_vulnlab_solved', JSON.stringify(solvedChallenges));
    } catch {
      // Storage quota or privacy sandbox fallback
    }
  }, [solvedChallenges]);

  const handleSolveChallenge = (id: string) => {
    if (!solvedChallenges.includes(id)) {
      setSolvedChallenges((prev) => [...prev, id]);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-indigo-600/30 selection:text-indigo-200">
      {/* Top Bar Contract (3 zones, single line) */}
      <Navbar
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        solvedCount={solvedChallenges.length}
        totalChallenges={CTF_CHALLENGES.length}
      />

      {/* Main Viewport Container */}
      <main className="flex-1 w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
        {activeTab === 'explorer' && (
          <VulnerabilityExplorer
            onLaunchChallenge={() => setActiveTab('challenges')}
          />
        )}

        {activeTab === 'matrix' && (
          <VersionMatrixView />
        )}

        {activeTab === 'challenges' && (
          <ChallengeArena
            solvedChallenges={solvedChallenges}
            onSolveChallenge={handleSolveChallenge}
          />
        )}

        {activeTab === 'hardening' && (
          <HardeningAuditor />
        )}

        {activeTab === 'tools' && (
          <PayloadToolsView />
        )}
      </main>

      {/* Quiet, Clean Editorial Footer */}
      <footer className="border-t border-slate-900 bg-slate-950 py-8 px-6 text-xs text-slate-500">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-indigo-400" />
            <span className="font-semibold text-slate-300">PHP VulnLab</span>
            <span aria-hidden="true">·</span>
            <span>Educational Cybersecurity Laboratory</span>
          </div>

          <div className="flex items-center gap-6">
            <button
              onClick={() => setActiveTab('explorer')}
              className="hover:text-slate-300 transition-colors flex items-center gap-1"
            >
              <BookOpen className="w-3.5 h-3.5" />
              <span>Vulnerabilities</span>
            </button>
            <button
              onClick={() => setActiveTab('matrix')}
              className="hover:text-slate-300 transition-colors flex items-center gap-1"
            >
              <Cpu className="w-3.5 h-3.5" />
              <span>PHP Matrix</span>
            </button>
            <button
              onClick={() => setActiveTab('challenges')}
              className="hover:text-slate-300 transition-colors flex items-center gap-1"
            >
              <Terminal className="w-3.5 h-3.5" />
              <span>CTF Drills</span>
            </button>
            <button
              onClick={() => setActiveTab('tools')}
              className="hover:text-slate-300 transition-colors flex items-center gap-1"
            >
              <Wrench className="w-3.5 h-3.5" />
              <span>Payload Tools</span>
            </button>
          </div>
        </div>
      </footer>
    </div>
  );
}
