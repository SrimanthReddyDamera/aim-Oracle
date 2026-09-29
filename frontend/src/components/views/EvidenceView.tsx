import React, { useState } from 'react';
import { IncidentInvestigation, EvidenceItem } from '../../types/oracle';
import { EvidenceCategoryBadge } from '../common/Badges';
import { Search, Filter, ShieldCheck, FileText, Database, GitCommit, ExternalLink } from 'lucide-react';

interface EvidenceViewProps {
  investigation: IncidentInvestigation;
}

export function EvidenceView({ investigation }: EvidenceViewProps) {
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedItem, setSelectedItem] = useState<EvidenceItem>(investigation.evidence[0]);

  const categories = ['ALL', 'LOG', 'CODE', 'GIT', 'METRIC', 'CONFIG'];

  const filtered = investigation.evidence.filter((item) => {
    const matchesCategory = selectedCategory === 'ALL' || item.category === selectedCategory;
    const matchesQuery =
      item.summary.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.source.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.content.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesCategory && matchesQuery;
  });

  return (
    <div className="p-6 lg:p-8 max-w-7xl mx-auto space-y-6 text-slate-200 dark:text-slate-200">
      <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-3 pb-4 border-b border-white/10">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold tracking-tight text-white font-heading font-bold">
              Evidence Artifact Vault
            </h1>
            <span className="text-[11px] font-medium px-2 py-0.5 rounded-full bg-slate-800/60 text-slate-300 dark:text-slate-300 border border-white/10 dark:border-slate-700">
              {investigation.evidence.length} Recorded
            </span>
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
            Cryptographically tracked evidence records supporting the investigation of {investigation.id}.
          </p>
        </div>

        {/* Filter / Search toolbar */}
        <div className="flex items-center gap-2">
          <div className="flex rounded-lg border border-white/10 dark:border-slate-700 p-0.5 bg-slate-800/60 text-[11px]">
            {categories.map((cat) => (
              <button
                key={cat}
                onClick={() => setSelectedCategory(cat)}
                className={`px-2.5 py-1 font-medium rounded-md transition-colors ${
                  selectedCategory === cat
                    ? 'bg-slate-900/80 dark:bg-slate-700 text-white font-heading font-bold font-semibold shadow-2xs'
                    : 'text-slate-500 dark:text-slate-400 hover:text-slate-200 dark:hover:text-slate-200'
                }`}
              >
                {cat}
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-12 gap-6 h-[640px]">
        {/* Artifacts List */}
        <div className="col-span-12 md:col-span-5 border border-white/10 bg-slate-900/80 rounded-xl overflow-y-auto divide-y divide-slate-100 dark:divide-slate-800/60 shadow-2xs">
          <div className="p-3 bg-slate-950/60/70 dark:bg-slate-800/40 border-b border-white/10">
            <div className="relative">
              <Search size={14} className="absolute left-2.5 top-2.5 text-slate-400" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search evidence records..."
                className="w-full bg-slate-900/80 border border-white/10 dark:border-slate-700 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 dark:text-slate-200 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500"
              />
            </div>
          </div>

          {filtered.length === 0 ? (
            <div className="p-8 text-center text-xs text-slate-400">
              No evidence matching the current filter.
            </div>
          ) : (
            filtered.map((item) => {
              const isSelected = selectedItem?.id === item.id;
              return (
                <div
                  key={item.id}
                  onClick={() => setSelectedItem(item)}
                  className={`p-3.5 cursor-pointer transition-colors ${
                    isSelected
                      ? 'bg-indigo-500/10/70 dark:bg-indigo-950/40 border-l-3 border-l-indigo-600 dark:border-l-indigo-400'
                      : 'hover:bg-slate-800/50 dark:hover:bg-slate-800/40'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono font-bold text-white font-heading font-bold">{item.id}</span>
                      <EvidenceCategoryBadge category={item.category} />
                    </div>
                    <span className="text-[11px] font-medium text-slate-400">{item.relevance}</span>
                  </div>
                  <div className="text-xs text-slate-200 dark:text-slate-200 font-medium line-clamp-1">{item.summary}</div>
                  <div className="text-[11px] text-slate-400 truncate mt-0.5">{item.source}</div>
                </div>
              );
            })
          )}
        </div>

        {/* Selected Artifact Detail */}
        <div className="col-span-12 md:col-span-7 border border-white/10 bg-slate-900/80 rounded-xl p-5 overflow-y-auto space-y-4 shadow-2xs">
          {selectedItem ? (
            <div className="space-y-4">
              <div className="flex justify-between items-start pb-3 border-b border-white/10">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-sm font-mono font-bold text-white font-heading font-bold">{selectedItem.id}</span>
                    <EvidenceCategoryBadge category={selectedItem.category} />
                    <span className="text-[11px] font-medium px-2 py-0.5 rounded bg-slate-800/60 text-slate-300 dark:text-slate-300">
                      {selectedItem.relevance} Relevance
                    </span>
                  </div>
                  <p className="text-xs text-slate-600 dark:text-slate-300">{selectedItem.summary}</p>
                </div>

                <div className="text-right">
                  <span className="text-[10px] uppercase font-semibold text-slate-400 block">Evaluated</span>
                  <span className="text-xs font-mono font-medium text-slate-300 dark:text-slate-300">{selectedItem.timestamp}</span>
                </div>
              </div>

              {/* Provenance Box */}
              <div className="p-3.5 rounded-lg border border-white/10 bg-slate-950/60/80 dark:bg-slate-800/40 text-xs space-y-2">
                <span className="text-[10px] text-slate-500 uppercase tracking-wider block font-semibold">
                  Telemetry Provenance & Chain of Custody
                </span>
                <div className="flex justify-between">
                  <span className="text-slate-500">Source:</span>
                  <span className="text-slate-200 dark:text-slate-200 font-mono">{selectedItem.source}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">Lineage:</span>
                  <span className="text-indigo-600 dark:text-indigo-400 font-mono truncate max-w-md">{selectedItem.provenance}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">Confidence:</span>
                  <span className="text-emerald-600 dark:text-emerald-400 font-bold font-mono">{selectedItem.confidence}%</span>
                </div>
              </div>

              {/* Raw Payload Preview */}
              <div className="space-y-1.5">
                <span className="text-xs font-semibold text-slate-300 dark:text-slate-300">
                  Extracted Raw Payload
                </span>
                <pre className="p-4 rounded-lg bg-slate-950 text-slate-100 border border-slate-800 text-xs font-mono overflow-x-auto leading-relaxed max-h-72">
                  {selectedItem.content}
                </pre>
              </div>
            </div>
          ) : (
            <div className="h-full flex items-center justify-center text-xs text-slate-400">
              Select an artifact on the left to inspect details.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
