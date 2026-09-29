import React, { useState, useEffect } from 'react';
import { 
  Search, 
  Terminal, 
  Layers, 
  FolderGit2, 
  FileCode2, 
  CheckCircle2, 
  ShieldCheck, 
  Sliders, 
  Award,
  Play,
  Cpu,
  FileCheck
} from 'lucide-react';

interface CommandPaletteProps {
  isOpen: boolean;
  onClose: () => void;
  onSelectTab: (tab: string) => void;
}

export function CommandPalette({ isOpen, onClose, onSelectTab }: CommandPaletteProps) {
  const [query, setQuery] = useState('');

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        onClose();
      }
      if (e.key === 'Escape' && isOpen) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  // Exact commands specified in section 31 of prompt
  const commands = [
    { 
      id: 'start-investigation', 
      label: 'Start Investigation', 
      category: 'Action', 
      icon: Terminal, 
      hint: 'Open new incident intake form and provide error telemetry',
      action: () => { onSelectTab('investigate'); onClose(); } 
    },
    { 
      id: 'search-investigation', 
      label: 'Search Investigation', 
      category: 'Workspace', 
      icon: Search, 
      hint: 'Inspect active incident workspace, root cause, and timeline',
      action: () => { onSelectTab('workspace'); onClose(); } 
    },
    { 
      id: 'open-evidence', 
      label: 'Open Evidence', 
      category: 'Evidence', 
      icon: FolderGit2, 
      hint: 'Inspect first-class evidence vault, provenance & diffs',
      action: () => { onSelectTab('evidence'); onClose(); } 
    },
    { 
      id: 'generate-agent-task', 
      label: 'Generate Agent Task', 
      category: 'Resolution', 
      icon: Cpu, 
      hint: 'Format remediation prompt for Claude Code, Codex, or CLI',
      action: () => { onSelectTab('agent-tasks'); onClose(); } 
    },
    { 
      id: 'run-sandbox-replay', 
      label: 'Run Sandbox Replay', 
      category: 'Verification', 
      icon: Play, 
      hint: 'Execute 5-stage container replay and test regression suite',
      action: () => { onSelectTab('verification'); onClose(); } 
    },
    { 
      id: 'open-verification', 
      label: 'Open Verification', 
      category: 'Verification', 
      icon: FileCheck, 
      hint: 'Inspect 4 Pillars of Proof and deployment gate status',
      action: () => { onSelectTab('verification'); onClose(); } 
    },
    { 
      id: 'view-certificate', 
      label: 'View Certificate', 
      category: 'Verification', 
      icon: Award, 
      hint: 'Inspect cryptographic Ed25519 attestation seal',
      action: () => { onSelectTab('verification'); onClose(); } 
    },
    { 
      id: 'open-audit-log', 
      label: 'Open Audit Log', 
      category: 'Security', 
      icon: ShieldCheck, 
      hint: 'View immutable audit events and evidence integrity records',
      action: () => { onSelectTab('security'); onClose(); } 
    },
  ];

  const filtered = commands.filter((c) =>
    c.label.toLowerCase().includes(query.toLowerCase()) ||
    c.category.toLowerCase().includes(query.toLowerCase()) ||
    c.hint.toLowerCase().includes(query.toLowerCase())
  );

  return (
    <div 
      className="fixed inset-0 z-50 flex items-start justify-center pt-20 px-4 bg-slate-900/60 dark:bg-black/80 backdrop-blur-xs"
      onClick={onClose}
    >
      <div 
        className="w-full max-w-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl shadow-2xl overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center px-4 py-3 border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/80">
          <Search size={16} className="text-slate-400 mr-2 shrink-0" />
          <input
            autoFocus
            type="text"
            placeholder="Type a command or search (e.g. Start Investigation, Verify, Certificate)..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="w-full bg-transparent text-xs text-slate-900 dark:text-slate-100 placeholder-slate-400 focus:outline-none font-sans"
          />
          <kbd className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-200 dark:bg-slate-800 text-slate-600 dark:text-slate-400 border border-slate-300 dark:border-slate-700">
            ESC
          </kbd>
        </div>

        <div className="max-h-80 overflow-y-auto p-2 divide-y divide-slate-100 dark:divide-slate-800/40">
          {filtered.length === 0 ? (
            <div className="py-8 text-center text-xs text-slate-400 font-sans">
              No matching commands found for &ldquo;{query}&rdquo;
            </div>
          ) : (
            filtered.map((cmd) => {
              const Icon = cmd.icon;
              return (
                <button
                  key={cmd.id}
                  onClick={cmd.action}
                  className="w-full flex items-center justify-between p-2.5 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors text-left group"
                >
                  <div className="flex items-center gap-3">
                    <div className="p-1.5 rounded-md bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 group-hover:bg-indigo-600 group-hover:text-white transition-colors">
                      <Icon size={14} />
                    </div>
                    <div>
                      <div className="text-xs font-semibold text-slate-800 dark:text-slate-200 group-hover:text-indigo-600 dark:group-hover:text-indigo-400 transition-colors">
                        {cmd.label}
                      </div>
                      <div className="text-[11px] text-slate-400">
                        {cmd.hint}
                      </div>
                    </div>
                  </div>
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-400 shrink-0">
                    {cmd.category}
                  </span>
                </button>
              );
            })
          )}
        </div>

        <div className="p-2.5 border-t border-slate-100 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/60 flex items-center justify-between text-[10px] text-slate-400 font-mono">
          <span>Shortcuts: ⌘K / Ctrl+K to toggle</span>
          <span>ORACLE Command Control</span>
        </div>
      </div>
    </div>
  );
}
