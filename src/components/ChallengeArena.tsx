import React, { useState } from 'react';
import { CTF_CHALLENGES } from '../data/challenges';
import { Challenge } from '../types';
import { Terminal, CheckCircle2, AlertCircle, HelpCircle, Shield, ChevronRight, Award } from 'lucide-react';

interface ChallengeArenaProps {
  solvedChallenges: string[];
  onSolveChallenge: (id: string) => void;
}

export const ChallengeArena: React.FC<ChallengeArenaProps> = ({
  solvedChallenges,
  onSolveChallenge
}) => {
  const [selectedChallenge, setSelectedChallenge] = useState<Challenge>(CTF_CHALLENGES[0]);
  const [userInput, setUserInput] = useState<string>(CTF_CHALLENGES[0].initialInput);
  const [showHint, setShowHint] = useState<boolean>(false);
  const [validationResult, setValidationResult] = useState<{
    success: boolean;
    flag?: string;
    message: string;
  } | null>(null);

  const handleSelectChallenge = (c: Challenge) => {
    setSelectedChallenge(c);
    setUserInput(c.initialInput);
    setShowHint(false);
    setValidationResult(null);
  };

  const handleTest = (e: React.FormEvent) => {
    e.preventDefault();
    const result = selectedChallenge.validateFlagOrPayload(userInput);
    setValidationResult(result);
    if (result.success && !solvedChallenges.includes(selectedChallenge.id)) {
      onSolveChallenge(selectedChallenge.id);
    }
  };

  const isCurrentSolved = solvedChallenges.includes(selectedChallenge.id);

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="flex items-center justify-between flex-wrap gap-4 p-5 bg-slate-900 border border-slate-800 rounded-xl">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <Award className="w-5 h-5 text-indigo-400" />
            <h2 className="text-base font-bold text-white">PHP Vulnerability CTF Arena</h2>
          </div>
          <p className="text-xs text-slate-400">
            Put your security skills to the test with real-world vulnerable PHP challenges. Extract flags, bypass authentication, and audit security flaws.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="text-right">
            <div className="text-xs text-slate-400 font-medium">Progress Score</div>
            <div className="text-lg font-bold font-mono text-indigo-300 tabular-nums">
              {solvedChallenges.length} / {CTF_CHALLENGES.length} Completed
            </div>
          </div>
          <div className="w-12 h-12 rounded-xl bg-slate-800 border border-slate-700 flex items-center justify-center font-bold text-sm text-indigo-400">
            {Math.round((solvedChallenges.length / CTF_CHALLENGES.length) * 100)}%
          </div>
        </div>
      </div>

      {/* Grid: Left Challenge List / Right Challenge Interactive Deck */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Column: Challenge Selector (4 Cols) */}
        <div className="lg:col-span-4 space-y-2">
          <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider px-1">
            Available Missions
          </div>
          <div className="space-y-1.5">
            {CTF_CHALLENGES.map((ch, idx) => {
              const isSelected = ch.id === selectedChallenge.id;
              const isSolved = solvedChallenges.includes(ch.id);

              return (
                <div
                  key={ch.id}
                  onClick={() => handleSelectChallenge(ch)}
                  className={`p-3 rounded-lg border transition-all cursor-pointer flex items-center justify-between gap-3 text-xs ${
                    isSelected
                      ? 'bg-slate-900 border-indigo-500 shadow-sm'
                      : 'bg-slate-900/60 border-slate-800 hover:border-slate-700 hover:bg-slate-900'
                  }`}
                >
                  <div className="space-y-1 truncate">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-[11px] text-slate-500">
                        0{idx + 1}.
                      </span>
                      <span className="font-semibold text-slate-200 truncate">
                        {ch.title}
                      </span>
                    </div>
                    <div className="flex items-center gap-2 text-[11px] text-slate-400">
                      <span>{ch.difficulty}</span>
                      <span aria-hidden="true">·</span>
                      <span className="capitalize">{ch.category.replace('-', ' ')}</span>
                    </div>
                  </div>

                  <div className="shrink-0">
                    {isSolved ? (
                      <span className="w-5 h-5 rounded-full bg-emerald-950 border border-emerald-700 text-emerald-400 flex items-center justify-center text-[10px]">
                        ✓
                      </span>
                    ) : (
                      <ChevronRight className="w-4 h-4 text-slate-600" />
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right Column: Active Challenge Workplace (8 Cols) */}
        <div className="lg:col-span-8 bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-5">
          {/* Challenge Title Bar */}
          <div className="flex items-start justify-between gap-3 pb-3 border-b border-slate-800">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <h3 className="text-base font-bold text-white">{selectedChallenge.title}</h3>
                <span className="text-[11px] px-2 py-0.5 rounded bg-slate-800 text-indigo-300 font-medium">
                  {selectedChallenge.difficulty}
                </span>
                {isCurrentSolved && (
                  <span className="text-[11px] px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 font-medium">
                    Solved
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                {selectedChallenge.scenario}
              </p>
            </div>
          </div>

          {/* Target Vulnerable Script */}
          <div className="space-y-2">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span className="font-medium">Target Server Script (PHP):</span>
            </div>
            <div className="bg-slate-950 rounded-lg border border-slate-800 p-3 font-mono text-xs overflow-x-auto">
              <pre className="text-slate-300 leading-relaxed whitespace-pre">
                {selectedChallenge.targetScript}
              </pre>
            </div>
          </div>

          {/* Goal & Objective */}
          <div className="p-3 bg-indigo-950/30 border border-indigo-900/40 rounded-lg text-xs space-y-1 text-slate-300">
            <div className="font-semibold text-indigo-300 flex items-center gap-1.5">
              <Terminal className="w-3.5 h-3.5" />
              <span>Mission Goal:</span>
            </div>
            <p>{selectedChallenge.goal}</p>
          </div>

          {/* Input & Form Submission */}
          <form onSubmit={handleTest} className="space-y-3">
            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1">
                Your Exploit Payload / Solution Input:
              </label>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={userInput}
                  onChange={(e) => setUserInput(e.target.value)}
                  placeholder="Enter your payload..."
                  className="flex-1 bg-slate-950 border border-slate-800 focus:border-indigo-500 rounded-lg px-3 py-2 text-xs font-mono text-indigo-200 placeholder-slate-600 outline-none"
                />
                <button
                  type="submit"
                  className="px-4 py-2 text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-500 active:bg-indigo-700 rounded-lg transition-colors whitespace-nowrap"
                >
                  Submit Payload
                </button>
              </div>
            </div>

            {/* Hint Accordion */}
            <div className="pt-1">
              <button
                type="button"
                onClick={() => setShowHint(!showHint)}
                className="text-xs text-slate-400 hover:text-slate-200 flex items-center gap-1.5 transition-colors"
              >
                <HelpCircle className="w-3.5 h-3.5 text-indigo-400" />
                <span>{showHint ? 'Hide Tactical Hint' : 'Need a hint?'}</span>
              </button>
              {showHint && (
                <div className="mt-2 p-3 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-300">
                  {selectedChallenge.hint}
                </div>
              )}
            </div>
          </form>

          {/* Validation Feedback Result */}
          {validationResult && (
            <div
              className={`p-4 rounded-xl border text-xs space-y-2 ${
                validationResult.success
                  ? 'bg-emerald-950/40 border-emerald-900/60 text-emerald-200'
                  : 'bg-rose-950/40 border-rose-900/60 text-rose-200'
              }`}
            >
              <div className="flex items-center gap-2 font-semibold">
                {validationResult.success ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                ) : (
                  <AlertCircle className="w-4 h-4 text-rose-400" />
                )}
                <span>
                  {validationResult.success ? 'Challenge Completed!' : 'Exploit Attempt Failed'}
                </span>
              </div>
              <p className="text-slate-300">{validationResult.message}</p>

              {validationResult.flag && (
                <div className="mt-2 p-2.5 bg-slate-950/80 rounded border border-emerald-800/80 flex items-center justify-between font-mono text-xs">
                  <span className="text-emerald-400 font-bold">{validationResult.flag}</span>
                  <span className="text-[10px] text-slate-400 uppercase">Captured Flag</span>
                </div>
              )}
            </div>
          )}

          {/* Remediation & How to Patch */}
          {(isCurrentSolved || validationResult?.success) && (
            <div className="p-4 bg-slate-950 border border-slate-800 rounded-lg space-y-2 text-xs">
              <div className="font-semibold text-slate-200 flex items-center gap-2">
                <Shield className="w-4 h-4 text-emerald-400" />
                <span>Security Patching Blueprint:</span>
              </div>
              <pre className="p-2.5 bg-slate-900 rounded border border-slate-800 font-mono text-[11px] text-indigo-300 overflow-x-auto">
                {selectedChallenge.patchCode}
              </pre>
              <p className="text-slate-400 leading-relaxed">
                {selectedChallenge.patchExplanation}
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
