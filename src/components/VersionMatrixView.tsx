import React, { useState } from 'react';
import { PHP_VERSION_MATRIX, VersionQuirk } from '../data/versionMatrix';
import { TypeJugglingLab } from './TypeJugglingLab';
import { Cpu, Search, AlertOctagon } from 'lucide-react';

export const VersionMatrixView: React.FC = () => {
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [expandedQuirk, setExpandedQuirk] = useState<string | null>(null);

  const categories = ['all', 'Type Juggling', 'File Inclusion & FS', 'Command & Code Eval', 'Object Deserialization'];

  const filteredQuirks = PHP_VERSION_MATRIX.filter((item: VersionQuirk) => {
    const matchesCategory = selectedCategory === 'all' || item.category === selectedCategory;
    const matchesSearch = item.expression.toLowerCase().includes(searchQuery.toLowerCase()) ||
                          item.explanation.toLowerCase().includes(searchQuery.toLowerCase()) ||
                          item.securityImpact.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesCategory && matchesSearch;
  });

  return (
    <div className="space-y-6">
      {/* Introduction */}
      <div className="p-5 bg-slate-900 border border-slate-800 rounded-xl space-y-2">
        <div className="flex items-center gap-2">
          <Cpu className="w-5 h-5 text-indigo-400" />
          <h2 className="text-base font-bold text-white">PHP Version Evolution & Security Quirk Matrix</h2>
        </div>
        <p className="text-xs text-slate-300 leading-relaxed max-w-4xl">
          PHP has evolved dramatically across major releases. Many historic vulnerabilities (such as silent string-to-zero casting in PHP 5 and 7, null byte truncation, and code evaluation inside <code className="text-indigo-300">assert()</code>) were resolved or fundamentally altered in PHP 8.0+. Explore the exact behavior discrepancies below.
        </p>
      </div>

      {/* Interactive Live Type Juggling Lab */}
      <TypeJugglingLab />

      {/* Filter and Search Bar */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        {/* Category Tabs */}
        <div className="flex items-center gap-1 p-1 bg-slate-900 border border-slate-800 rounded-lg overflow-x-auto max-w-full">
          {categories.map((cat) => (
            <button
              key={cat}
              onClick={() => setSelectedCategory(cat)}
              className={`px-3 py-1.5 text-xs font-medium rounded-md whitespace-nowrap transition-colors ${
                selectedCategory === cat
                  ? 'bg-indigo-600 text-white shadow-xs'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {cat === 'all' ? 'All Behaviors' : cat}
            </button>
          ))}
        </div>

        {/* Search */}
        <div className="relative min-w-[240px]">
          <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search expressions, CVEs..."
            className="w-full bg-slate-900 border border-slate-800 focus:border-indigo-500 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 outline-none"
          />
        </div>
      </div>

      {/* Version Matrix Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950 border-b border-slate-800 text-slate-400 font-semibold uppercase tracking-wider text-[11px]">
              <tr>
                <th className="py-3 px-4">Expression / Behavior</th>
                <th className="py-3 px-4">PHP 5.6</th>
                <th className="py-3 px-4">PHP 7.4</th>
                <th className="py-3 px-4">PHP 8.0 - 8.4</th>
                <th className="py-3 px-4">Security Impact</th>
                <th className="py-3 px-4 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 bg-slate-900/50">
              {filteredQuirks.map((quirk) => {
                const isExpanded = expandedQuirk === quirk.id;
                return (
                  <React.Fragment key={quirk.id}>
                    <tr className="hover:bg-slate-800/40 transition-colors">
                      <td className="py-3 px-4 font-mono font-semibold text-indigo-300">
                        {quirk.expression}
                      </td>
                      <td className="py-3 px-4 font-mono text-slate-300">
                        {quirk.php5}
                      </td>
                      <td className="py-3 px-4 font-mono text-slate-300">
                        {quirk.php7}
                      </td>
                      <td className="py-3 px-4 font-mono font-medium text-emerald-400">
                        {quirk.php8}
                      </td>
                      <td className="py-3 px-4">
                        <span className="flex items-center gap-1.5 text-slate-300 font-medium">
                          <AlertOctagon className={`w-3.5 h-3.5 ${
                            quirk.securityImpact.includes('Critical') ? 'text-rose-400' : 'text-amber-400'
                          }`} />
                          <span>{quirk.securityImpact}</span>
                        </span>
                      </td>
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={() => setExpandedQuirk(isExpanded ? null : quirk.id)}
                          className="text-xs text-indigo-400 hover:text-indigo-300 underline font-medium"
                        >
                          {isExpanded ? 'Hide' : 'Explain'}
                        </button>
                      </td>
                    </tr>
                    {isExpanded && (
                      <tr className="bg-slate-950/80">
                        <td colSpan={6} className="py-3 px-4 border-b border-slate-800">
                          <div className="text-xs text-slate-300 leading-relaxed space-y-1">
                            <span className="font-semibold text-indigo-300">Internal Architectural Reason: </span>
                            <span>{quirk.explanation}</span>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
