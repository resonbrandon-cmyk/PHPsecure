import React, { useState } from 'react';
import { HelpCircle, ArrowRightLeft } from 'lucide-react';

export const TypeJugglingLab: React.FC = () => {
  const [valA, setValA] = useState<string>('"0e123456"');
  const [valB, setValB] = useState<string>('"0e987654"');

  const presetPairs = [
    { label: 'Magic Hashes', a: '"0e123456"', b: '"0e987654"' },
    { label: 'String to Zero', a: '"0"', b: '0' },
    { label: 'Alphanumeric to Int', a: '"42admin"', b: '42' },
    { label: 'String "foo" vs 0', a: '"foo"', b: '0' },
    { label: 'Boolean "false" vs false', a: '"false"', b: 'false' },
    { label: 'Empty String vs False', a: '""', b: 'false' },
    { label: 'Null vs 0', a: 'null', b: '0' },
    { label: 'Array vs Null', a: '[]', b: 'null' }
  ];

  const evaluatePHP = (a: string, b: string, mode: 'php7' | 'php8') => {
    // Exact PHP logic reproduction
    const parse = (v: string) => {
      const trimmed = v.trim();
      if (trimmed === 'true') return { type: 'bool', val: true };
      if (trimmed === 'false') return { type: 'bool', val: false };
      if (trimmed === 'null') return { type: 'null', val: null };
      if (trimmed === '[]') return { type: 'array', val: [] };
      if (/^-?\d+$/.test(trimmed)) return { type: 'int', val: parseInt(trimmed, 10) };
      if (/^-?\d+\.\d+$/.test(trimmed)) return { type: 'float', val: parseFloat(trimmed) };
      if ((trimmed.startsWith('"') && trimmed.endsWith('"')) || (trimmed.startsWith("'") && trimmed.endsWith("'"))) {
        return { type: 'string', val: trimmed.slice(1, -1) };
      }
      return { type: 'string', val: trimmed };
    };

    const parsedA = parse(a);
    const parsedB = parse(b);

    // Strict identity
    const isStrictEqual = parsedA.type === parsedB.type && parsedA.val === parsedB.val;

    // Loose equality rules
    let isLooseEqual = false;
    let reason = '';

    // Check magic hashes
    const isMagicHashA = parsedA.type === 'string' && typeof parsedA.val === 'string' && /^0e\d+$/i.test(parsedA.val);
    const isMagicHashB = parsedB.type === 'string' && typeof parsedB.val === 'string' && /^0e\d+$/i.test(parsedB.val);

    if (isMagicHashA && isMagicHashB) {
      isLooseEqual = true;
      reason = 'Both strings match scientific float format (0 * 10^x). Both cast to float(0.0).';
    } else if (mode === 'php7') {
      if (parsedA.type === 'string' && parsedB.type === 'int') {
        const parsedIntA = parseInt(parsedA.val as string, 10) || 0;
        isLooseEqual = parsedIntA === (parsedB.val as number);
        reason = `PHP 7 casts string "${parsedA.val}" to int(${parsedIntA}) before comparison.`;
      } else if (parsedA.type === 'int' && parsedB.type === 'string') {
        const parsedIntB = parseInt(parsedB.val as string, 10) || 0;
        isLooseEqual = (parsedA.val as number) === parsedIntB;
        reason = `PHP 7 casts string "${parsedB.val}" to int(${parsedIntB}) before comparison.`;
      } else if (parsedA.type === 'string' && parsedB.type === 'bool') {
        const boolA = (parsedA.val as string) !== '' && (parsedA.val as string) !== '0';
        isLooseEqual = boolA === parsedB.val;
        reason = `PHP casts string to boolean: non-empty non-"0" string is ${boolA}.`;
      } else {
        isLooseEqual = (parsedA.val as unknown) == (parsedB.val as unknown);
        reason = 'Standard PHP 7 type conversion.';
      }
    } else {
      // PHP 8 behavior
      if (parsedA.type === 'string' && parsedB.type === 'int') {
        const isNumericString = /^-?\d+$/.test(parsedA.val as string);
        if (isNumericString) {
          isLooseEqual = parseInt(parsedA.val as string, 10) === (parsedB.val as number);
          reason = 'PHP 8 only compares as numbers if string is purely numeric.';
        } else {
          isLooseEqual = false;
          reason = 'PHP 8 treats non-numeric string compared to number as FALSE without casting.';
        }
      } else if (parsedA.type === 'int' && parsedB.type === 'string') {
        const isNumericString = /^-?\d+$/.test(parsedB.val as string);
        if (isNumericString) {
          isLooseEqual = (parsedA.val as number) === parseInt(parsedB.val as string, 10);
          reason = 'PHP 8 compares numeric string numerically.';
        } else {
          isLooseEqual = false;
          reason = 'PHP 8 treats number compared to non-numeric string as FALSE.';
        }
      } else {
        isLooseEqual = (parsedA.val as unknown) == (parsedB.val as unknown);
        reason = 'Standard PHP 8 evaluation.';
      }
    }

    return { isStrictEqual, isLooseEqual, reason };
  };

  const php7Res = evaluatePHP(valA, valB, 'php7');
  const php8Res = evaluatePHP(valA, valB, 'php8');

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div className="flex items-center gap-2">
          <ArrowRightLeft className="w-4 h-4 text-indigo-400" />
          <h3 className="text-sm font-semibold text-white">Live PHP Type Juggling Evaluation Matrix</h3>
        </div>
        <div className="text-xs text-slate-400">
          Comparing <code className="text-indigo-300">==</code> vs <code className="text-emerald-300">===</code>
        </div>
      </div>

      {/* Preset Pickers */}
      <div className="space-y-1.5">
        <div className="text-xs text-slate-400">Quick Test Pairs:</div>
        <div className="flex flex-wrap gap-1.5">
          {presetPairs.map((p, idx) => (
            <button
              key={idx}
              onClick={() => { setValA(p.a); setValB(p.b); }}
              className="text-xs px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded transition-colors"
            >
              {p.label}
            </button>
          ))}
        </div>
      </div>

      {/* Inputs */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 font-mono text-xs">
        <div>
          <label className="block text-slate-400 mb-1">Operand A:</label>
          <input
            type="text"
            value={valA}
            onChange={(e) => setValA(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 focus:border-indigo-500 rounded px-3 py-2 text-indigo-300 outline-none"
            placeholder='"0e12345" or 0 or "foo"'
          />
        </div>
        <div>
          <label className="block text-slate-400 mb-1">Operand B:</label>
          <input
            type="text"
            value={valB}
            onChange={(e) => setValB(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 focus:border-indigo-500 rounded px-3 py-2 text-indigo-300 outline-none"
            placeholder='"0e99999" or "42"'
          />
        </div>
      </div>

      {/* Comparison Results Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-2">
        {/* PHP 5 / 7 Loose Comparison */}
        <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg space-y-1.5">
          <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
            PHP 5 & 7 (Loose ==)
          </div>
          <div className="text-lg font-bold font-mono">
            {php7Res.isLooseEqual ? (
              <span className="text-rose-400">TRUE (Equal)</span>
            ) : (
              <span className="text-slate-400">FALSE</span>
            )}
          </div>
          <div className="text-xs text-slate-400 leading-snug">
            {php7Res.reason}
          </div>
        </div>

        {/* PHP 8+ Loose Comparison */}
        <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg space-y-1.5">
          <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
            PHP 8+ (Loose ==)
          </div>
          <div className="text-lg font-bold font-mono">
            {php8Res.isLooseEqual ? (
              <span className="text-amber-400">TRUE (Equal)</span>
            ) : (
              <span className="text-emerald-400">FALSE (Safe)</span>
            )}
          </div>
          <div className="text-xs text-slate-400 leading-snug">
            {php8Res.reason}
          </div>
        </div>

        {/* Strict Comparison (===) */}
        <div className="p-3 bg-slate-950 border border-emerald-900/60 rounded-lg space-y-1.5">
          <div className="text-[11px] font-semibold text-emerald-400 uppercase tracking-wider">
            Strict Identity (===)
          </div>
          <div className="text-lg font-bold font-mono">
            {php7Res.isStrictEqual ? (
              <span className="text-emerald-400">TRUE</span>
            ) : (
              <span className="text-emerald-300">FALSE (Strict Safe)</span>
            )}
          </div>
          <div className="text-xs text-slate-400 leading-snug">
            {php7Res.isStrictEqual
              ? 'Both type and value match identically.'
              : 'Types or values do not match; no implicit conversion allowed.'}
          </div>
        </div>
      </div>

      <div className="flex items-start gap-2 p-3 bg-slate-950/40 rounded-lg border border-slate-800 text-xs text-slate-400">
        <HelpCircle className="w-4 h-4 text-indigo-400 shrink-0 mt-0.5" />
        <span>
          <strong>Security Takeaway:</strong> Even though PHP 8 patched alphanumeric casting (e.g., <code className="text-slate-300">"42admin" == 42</code> is now false), magic hashes like <code className="text-slate-300">"0e123" == "0e456"</code> still evaluate to true across all PHP versions! Always use <code className="text-emerald-400">===</code> or <code className="text-emerald-400">hash_equals()</code>.
        </span>
      </div>
    </div>
  );
};
