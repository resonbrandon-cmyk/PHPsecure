import React from 'react';
import { Shield, Terminal, BookOpen, Cpu, Wrench } from 'lucide-react';

interface NavbarProps {
  activeTab: 'explorer' | 'matrix' | 'challenges' | 'hardening' | 'tools';
  onSelectTab: (tab: 'explorer' | 'matrix' | 'challenges' | 'hardening' | 'tools') => void;
  solvedCount: number;
  totalChallenges: number;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  onSelectTab,
  solvedCount,
  totalChallenges
}) => {
  return (
    <header className="sticky top-0 z-50 flex items-center justify-between gap-8 px-6 py-4 bg-slate-900/95 backdrop-blur-md border-b border-slate-800">
      {/* Zone 1: Brand Wordmark (Single text element) */}
      <div 
        onClick={() => onSelectTab('explorer')}
        className="flex items-center gap-2.5 text-lg font-bold tracking-tight text-white whitespace-nowrap shrink-0 cursor-pointer select-none"
      >
        <div className="w-8 h-8 rounded-lg bg-indigo-600 flex items-center justify-center text-white shadow-sm">
          <Shield className="w-4 h-4 text-white" />
        </div>
        <span>PHP VulnLab</span>
      </div>

      {/* Zone 2: Clean single-line text navigation links */}
      <nav className="hidden md:flex items-center gap-6 text-sm font-medium text-slate-300">
        <button
          onClick={() => onSelectTab('explorer')}
          className={`flex items-center gap-1.5 whitespace-nowrap shrink-0 transition-colors py-1 ${
            activeTab === 'explorer' 
              ? 'text-white font-semibold border-b-2 border-indigo-500' 
              : 'text-slate-400 hover:text-slate-100'
          }`}
        >
          <BookOpen className="w-4 h-4" />
          <span>Vulnerabilities</span>
        </button>

        <button
          onClick={() => onSelectTab('matrix')}
          className={`flex items-center gap-1.5 whitespace-nowrap shrink-0 transition-colors py-1 ${
            activeTab === 'matrix' 
              ? 'text-white font-semibold border-b-2 border-indigo-500' 
              : 'text-slate-400 hover:text-slate-100'
          }`}
        >
          <Cpu className="w-4 h-4" />
          <span>Version Matrix</span>
        </button>

        <button
          onClick={() => onSelectTab('challenges')}
          className={`flex items-center gap-1.5 whitespace-nowrap shrink-0 transition-colors py-1 ${
            activeTab === 'challenges' 
              ? 'text-white font-semibold border-b-2 border-indigo-500' 
              : 'text-slate-400 hover:text-slate-100'
          }`}
        >
          <Terminal className="w-4 h-4" />
          <span>CTF Challenges</span>
          <span className="text-xs text-indigo-400 font-mono tabular-nums ml-0.5">
            ({solvedCount}/{totalChallenges})
          </span>
        </button>

        <button
          onClick={() => onSelectTab('hardening')}
          className={`flex items-center gap-1.5 whitespace-nowrap shrink-0 transition-colors py-1 ${
            activeTab === 'hardening' 
              ? 'text-white font-semibold border-b-2 border-indigo-500' 
              : 'text-slate-400 hover:text-slate-100'
          }`}
        >
          <Shield className="w-4 h-4" />
          <span>php.ini Hardening</span>
        </button>

        <button
          onClick={() => onSelectTab('tools')}
          className={`flex items-center gap-1.5 whitespace-nowrap shrink-0 transition-colors py-1 ${
            activeTab === 'tools' 
              ? 'text-white font-semibold border-b-2 border-indigo-500' 
              : 'text-slate-400 hover:text-slate-100'
          }`}
        >
          <Wrench className="w-4 h-4" />
          <span>Payload Tools</span>
        </button>
      </nav>

      {/* Zone 3: 1 Primary Action */}
      <div className="flex items-center gap-3 shrink-0">
        <button
          onClick={() => onSelectTab('challenges')}
          className="px-4 py-2 text-xs font-semibold text-white bg-indigo-600 rounded-lg hover:bg-indigo-500 active:bg-indigo-700 transition-colors whitespace-nowrap shrink-0 shadow-sm flex items-center gap-2"
        >
          <Terminal className="w-3.5 h-3.5" />
          <span>Start CTF Challenge</span>
        </button>
      </div>
    </header>
  );
};
