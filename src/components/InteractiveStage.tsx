import React, { useState } from 'react';
import { VulnerabilityTopic, PhpVersion, ExploitPreset } from '../types';
import { Play, RotateCcw, AlertTriangle, CheckCircle, Terminal, Cpu, Database, ChevronRight, ChevronLeft } from 'lucide-react';

interface InteractiveStageProps {
  topic: VulnerabilityTopic;
}

export const InteractiveStage: React.FC<InteractiveStageProps> = ({ topic }) => {
  const [payload, setPayload] = useState<string>(topic.defaultPayload);
  const [selectedVersion, setSelectedVersion] = useState<PhpVersion>('php7');
  const [activeTab, setActiveTab] = useState<'trace' | 'terminal' | 'memory'>('trace');
  const [activeStepIndex, setActiveStepIndex] = useState<number>(0);
  const [hasRun, setHasRun] = useState<boolean>(true);

  // Compute live simulation based on current payload and version
  const simResult = topic.simulateExecution(payload, selectedVersion);

  const handleSelectPreset = (preset: ExploitPreset) => {
    setPayload(preset.payload);
    setActiveStepIndex(0);
    setHasRun(true);
  };

  const handleReset = () => {
    setPayload(topic.defaultPayload);
    setActiveStepIndex(0);
    setHasRun(true);
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden flex flex-col h-full shadow-sm">
      {/* Sandbox Header / Parameter Deck */}
      <div className="p-4 border-b border-slate-800 bg-slate-900/80 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <span className="text-xs font-semibold text-slate-300">Target Runtime:</span>
            <div className="flex items-center gap-1 p-0.5 bg-slate-800 rounded-lg">
              {(['php5', 'php7', 'php8'] as PhpVersion[]).map((ver) => (
                <button
                  key={ver}
                  onClick={() => { setSelectedVersion(ver); setActiveStepIndex(0); }}
                  className={`px-2.5 py-1 text-xs font-medium rounded-md whitespace-nowrap transition-colors ${
                    selectedVersion === ver
                      ? 'bg-indigo-600 text-white shadow-xs'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {ver === 'php5' ? 'PHP 5.6' : ver === 'php7' ? 'PHP 7.4' : 'PHP 8.2'}
                </button>
              ))}
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleReset}
              className="p-1.5 text-xs text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded-md transition-colors"
              title="Reset to default payload"
            >
              <RotateCcw className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => { setHasRun(true); setActiveStepIndex(simResult.executionTrace.length - 1); }}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-500 rounded-lg transition-colors shadow-xs"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>Simulate Exploit</span>
            </button>
          </div>
        </div>

        {/* Input Field */}
        <div>
          <label className="block text-xs font-medium text-slate-400 mb-1">
            HTTP Input / Exploit Payload (GET / POST / Header):
          </label>
          <div className="relative">
            <input
              type="text"
              value={payload}
              onChange={(e) => {
                setPayload(e.target.value);
                setActiveStepIndex(0);
                setHasRun(true);
              }}
              className="w-full bg-slate-950 border border-slate-800 focus:border-indigo-500 rounded-lg px-3 py-2 text-xs font-mono text-indigo-200 placeholder-slate-600 outline-none transition-colors"
              placeholder="Enter input or exploit payload..."
            />
          </div>
        </div>

        {/* Curated Exploit Presets */}
        <div>
          <div className="text-xs text-slate-400 mb-1.5 font-medium">Curated Exploit Presets:</div>
          <div className="flex flex-wrap gap-1.5">
            {topic.presets.map((preset) => {
              const isSelected = payload === preset.payload;
              return (
                <button
                  key={preset.id}
                  onClick={() => handleSelectPreset(preset)}
                  className={`text-xs px-2.5 py-1 rounded-md transition-colors text-left flex items-center gap-1.5 ${
                    isSelected
                      ? 'bg-indigo-950/80 border border-indigo-600/60 text-indigo-200 font-medium'
                      : 'bg-slate-800/80 hover:bg-slate-800 text-slate-300 border border-transparent'
                  }`}
                >
                  <span className={`w-1.5 h-1.5 rounded-full ${
                    preset.severity === 'Critical' ? 'bg-rose-500' : 'bg-amber-500'
                  }`} />
                  <span className="truncate max-w-[200px]">{preset.name}</span>
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* Security State Banner */}
      {hasRun && (
        <div className={`px-4 py-2.5 border-b flex items-start gap-2.5 text-xs ${
          simResult.isVulnerable
            ? 'bg-rose-950/40 border-rose-900/60 text-rose-200'
            : 'bg-emerald-950/30 border-emerald-900/50 text-emerald-200'
        }`}>
          {simResult.isVulnerable ? (
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
          ) : (
            <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
          )}
          <div className="space-y-0.5">
            <div className="font-semibold">
              {simResult.isVulnerable
                ? 'Vulnerability Exploit Successful'
                : 'Execution Contained / Non-Exploitable Result'}
            </div>
            <div className="text-slate-300">
              {simResult.securityAlert || (simResult.isVulnerable
                ? 'The provided payload successfully abused the insecure PHP construct.'
                : 'Input did not trigger critical code execution or bypass in this simulated environment.')}
            </div>
          </div>
        </div>
      )}

      {/* Tab Navigation for Sandbox Views */}
      <div className="flex items-center border-b border-slate-800 bg-slate-950 px-4">
        <button
          onClick={() => setActiveTab('trace')}
          className={`flex items-center gap-1.5 py-2.5 px-3 text-xs font-medium border-b-2 transition-colors ${
            activeTab === 'trace'
              ? 'border-indigo-500 text-white'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Cpu className="w-3.5 h-3.5" />
          <span>Zend VM Execution Trace</span>
          <span className="font-mono text-slate-500 text-[10px] tabular-nums">
            ({simResult.executionTrace.length} steps)
          </span>
        </button>

        <button
          onClick={() => setActiveTab('terminal')}
          className={`flex items-center gap-1.5 py-2.5 px-3 text-xs font-medium border-b-2 transition-colors ${
            activeTab === 'terminal'
              ? 'border-indigo-500 text-white'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Terminal className="w-3.5 h-3.5" />
          <span>Server Output & Terminal</span>
          <span className={`text-[10px] font-mono px-1 rounded ${
            simResult.serverStatus === 200 ? 'text-emerald-400 bg-emerald-950/60' : 'text-amber-400 bg-amber-950/60'
          }`}>
            {simResult.serverStatus}
          </span>
        </button>

        <button
          onClick={() => setActiveTab('memory')}
          className={`flex items-center gap-1.5 py-2.5 px-3 text-xs font-medium border-b-2 transition-colors ${
            activeTab === 'memory'
              ? 'border-indigo-500 text-white'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Database className="w-3.5 h-3.5" />
          <span>PHP Memory & Zvals</span>
        </button>
      </div>

      {/* Tab Contents */}
      <div className="flex-1 p-4 overflow-y-auto min-h-[300px] bg-slate-950/60">
        {activeTab === 'trace' && (
          <div className="space-y-3">
            {/* Step Controls */}
            <div className="flex items-center justify-between text-xs text-slate-400 pb-2 border-b border-slate-800/80">
              <span className="font-medium">
                Step <span className="font-mono text-white tabular-nums">{activeStepIndex + 1}</span> of{' '}
                <span className="font-mono tabular-nums">{simResult.executionTrace.length}</span>
              </span>
              <div className="flex items-center gap-1">
                <button
                  disabled={activeStepIndex === 0}
                  onClick={() => setActiveStepIndex((prev) => Math.max(0, prev - 1))}
                  className="p-1 rounded bg-slate-800 disabled:opacity-40 hover:bg-slate-700 text-slate-200"
                  title="Previous Step"
                >
                  <ChevronLeft className="w-3.5 h-3.5" />
                </button>
                <button
                  disabled={activeStepIndex === simResult.executionTrace.length - 1}
                  onClick={() => setActiveStepIndex((prev) => Math.min(simResult.executionTrace.length - 1, prev + 1))}
                  className="p-1 rounded bg-slate-800 disabled:opacity-40 hover:bg-slate-700 text-slate-200"
                  title="Next Step"
                >
                  <ChevronRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>

            {/* Stepper Timeline */}
            <div className="space-y-2.5">
              {simResult.executionTrace.map((step, idx) => {
                const isActive = idx === activeStepIndex;
                const isPast = idx <= activeStepIndex;

                let badgeColor = 'bg-slate-800 text-slate-300 border-slate-700';
                if (step.type === 'vulnerability') {
                  badgeColor = 'bg-rose-950 text-rose-300 border-rose-800';
                } else if (step.type === 'blocked') {
                  badgeColor = 'bg-amber-950 text-amber-300 border-amber-800';
                } else if (step.type === 'success') {
                  badgeColor = 'bg-emerald-950 text-emerald-300 border-emerald-800';
                }

                return (
                  <div
                    key={step.step}
                    onClick={() => setActiveStepIndex(idx)}
                    className={`p-3 rounded-lg border transition-all cursor-pointer text-xs ${
                      isActive
                        ? 'border-indigo-500 bg-slate-900 shadow-sm'
                        : isPast
                        ? 'border-slate-800 bg-slate-900/50 opacity-90 hover:opacity-100'
                        : 'border-slate-800/40 bg-slate-950/40 opacity-50'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2 mb-1">
                      <div className="flex items-center gap-2">
                        <span className="w-5 h-5 rounded flex items-center justify-center font-mono font-bold text-[10px] bg-slate-800 text-indigo-300">
                          {step.step}
                        </span>
                        <span className="font-semibold text-slate-200">{step.phase}</span>
                      </div>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-medium border ${badgeColor}`}>
                        {step.type.toUpperCase()}
                      </span>
                    </div>

                    <p className="text-slate-300 pl-7 leading-relaxed">{step.description}</p>

                    {step.stateChange && (
                      <div className="mt-2 pl-7">
                        <div className="inline-block px-2 py-1 rounded bg-slate-950 border border-slate-800 font-mono text-[11px] text-indigo-300">
                          {step.stateChange}
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {activeTab === 'terminal' && (
          <div className="space-y-3 font-mono text-xs">
            {/* Headers panel */}
            <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg text-slate-400 space-y-1">
              <div className="text-[11px] font-semibold text-slate-300 uppercase tracking-wider mb-1">
                HTTP Response Headers
              </div>
              <div className="text-emerald-400">HTTP/1.1 {simResult.serverStatus} {simResult.serverStatus === 200 ? 'OK' : 'Error'}</div>
              {Object.entries(simResult.headers).map(([k, v]) => (
                <div key={k}>
                  <span className="text-indigo-400">{k}:</span> <span className="text-slate-300">{v}</span>
                </div>
              ))}
            </div>

            {/* Terminal Body */}
            <div className="p-4 bg-slate-950 border border-slate-800 rounded-lg overflow-x-auto">
              <div className="text-slate-500 mb-2 border-b border-slate-800 pb-1 text-[11px]">
                # Server Stdout / Response Payload Output:
              </div>
              <pre className="text-slate-200 whitespace-pre-wrap leading-relaxed">
                {simResult.output}
              </pre>
            </div>
          </div>
        )}

        {activeTab === 'memory' && (
          <div className="space-y-3">
            <div className="text-xs text-slate-400">
              Snapshot of PHP runtime symbol table, internal zvals, and evaluation flags:
            </div>
            {simResult.memoryState ? (
              <div className="border border-slate-800 rounded-lg overflow-hidden">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-900 border-b border-slate-800 text-slate-400 font-medium">
                    <tr>
                      <th className="py-2.5 px-3">Symbol / Internal Variable</th>
                      <th className="py-2.5 px-3">Zend State / Value</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800 bg-slate-950 font-mono text-[11px]">
                    {Object.entries(simResult.memoryState).map(([k, v]) => (
                      <tr key={k} className="hover:bg-slate-900/40">
                        <td className="py-2 px-3 text-indigo-400 font-medium">{k}</td>
                        <td className="py-2 px-3 text-slate-300 break-all">{v}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="text-xs text-slate-500 italic p-4 text-center">
                No active symbol mutations recorded for this state.
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
