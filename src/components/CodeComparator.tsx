import React, { useState } from 'react';
import { VulnerabilityTopic } from '../types';
import { ShieldCheck, ShieldAlert, Copy, Check, FileCode, CheckCircle2 } from 'lucide-react';

interface CodeComparatorProps {
  topic: VulnerabilityTopic;
}

export const CodeComparator: React.FC<CodeComparatorProps> = ({ topic }) => {
  const [activeView, setActiveView] = useState<'vulnerable' | 'patched' | 'side-by-side'>('side-by-side');
  const [copiedType, setCopiedType] = useState<string | null>(null);

  const handleCopy = (text: string, type: string) => {
    navigator.clipboard.writeText(text);
    setCopiedType(type);
    setTimeout(() => setCopiedType(null), 2000);
  };

  const renderCodeBlock = (code: string, isPatched: boolean) => {
    const lines = code.trim().split('\n');
    return (
      <div className="bg-slate-950 rounded-lg border border-slate-800 overflow-hidden text-xs font-mono">
        <div className="flex items-center justify-between px-3 py-2 border-b border-slate-800 bg-slate-900/60">
          <div className="flex items-center gap-2">
            {isPatched ? (
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
            ) : (
              <ShieldAlert className="w-4 h-4 text-rose-400" />
            )}
            <span className="font-semibold text-slate-200">
              {isPatched ? 'Remediated & Hardened PHP Code' : 'Vulnerable Implementation'}
            </span>
          </div>

          <button
            onClick={() => handleCopy(code, isPatched ? 'patched' : 'vuln')}
            className="flex items-center gap-1 px-2 py-1 text-[11px] text-slate-400 hover:text-slate-200 bg-slate-800/80 rounded transition-colors"
          >
            {copiedType === (isPatched ? 'patched' : 'vuln') ? (
              <>
                <Check className="w-3 h-3 text-emerald-400" />
                <span className="text-emerald-400">Copied</span>
              </>
            ) : (
              <>
                <Copy className="w-3 h-3" />
                <span>Copy</span>
              </>
            )}
          </button>
        </div>

        <div className="p-3 overflow-x-auto max-h-[380px]">
          <pre className="text-slate-300 leading-5">
            {lines.map((line, idx) => (
              <div key={idx} className="table-row">
                <span className="table-cell pr-4 text-slate-600 select-none text-right tabular-nums w-8">
                  {idx + 1}
                </span>
                <span className="table-cell whitespace-pre">
                  {line}
                </span>
              </div>
            ))}
          </pre>
        </div>
      </div>
    );
  };

  return (
    <div className="space-y-6">
      {/* Code Viewer Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-2">
          <FileCode className="w-4 h-4 text-indigo-400" />
          <h3 className="text-sm font-semibold text-white">Code Anatomy & Remediation Diff</h3>
        </div>

        {/* View Toggle */}
        <div className="flex items-center gap-1 p-0.5 bg-slate-900 border border-slate-800 rounded-lg">
          <button
            onClick={() => setActiveView('side-by-side')}
            className={`px-3 py-1 text-xs font-medium rounded-md whitespace-nowrap transition-colors ${
              activeView === 'side-by-side'
                ? 'bg-indigo-600 text-white'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Side by Side
          </button>
          <button
            onClick={() => setActiveView('vulnerable')}
            className={`px-3 py-1 text-xs font-medium rounded-md whitespace-nowrap transition-colors ${
              activeView === 'vulnerable'
                ? 'bg-rose-900 text-rose-200'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Vulnerable Only
          </button>
          <button
            onClick={() => setActiveView('patched')}
            className={`px-3 py-1 text-xs font-medium rounded-md whitespace-nowrap transition-colors ${
              activeView === 'patched'
                ? 'bg-emerald-900 text-emerald-200'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Patched Only
          </button>
        </div>
      </div>

      {/* Code Blocks Container */}
      <div className={`grid gap-4 ${activeView === 'side-by-side' ? 'grid-cols-1 xl:grid-cols-2' : 'grid-cols-1'}`}>
        {(activeView === 'side-by-side' || activeView === 'vulnerable') && (
          <div>{renderCodeBlock(topic.vulnerableSnippet, false)}</div>
        )}
        {(activeView === 'side-by-side' || activeView === 'patched') && (
          <div>{renderCodeBlock(topic.patchedSnippet, true)}</div>
        )}
      </div>

      {/* Deep-Dive Technical Mechanics & Explanations */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Core Root Cause & Attack Mechanics */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-3">
          <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-rose-500" />
            Vulnerability Root Cause & Mechanics
          </h4>
          <p className="text-xs text-slate-300 leading-relaxed">
            {topic.rootCause}
          </p>
          <div className="space-y-2 pt-2 border-t border-slate-800">
            {topic.explanationPoints.map((point, index) => (
              <div key={index} className="flex items-start gap-2 text-xs text-slate-300">
                <span className="font-mono text-indigo-400 shrink-0 text-[11px] mt-0.5">0{index + 1}.</span>
                <span className="leading-relaxed">{point}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Defense-in-Depth Remediation Steps */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-3">
          <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-500" />
            Remediation & Defense-in-Depth
          </h4>
          <div className="space-y-2.5">
            {topic.remediationSteps.map((step, index) => (
              <div key={index} className="flex items-start gap-2.5 text-xs text-slate-300">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                <span className="leading-relaxed">{step}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
