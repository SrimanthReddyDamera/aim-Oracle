import React from 'react';
import { Severity, InvestigationStage, EvidenceCategory } from '../../types/oracle';
import { 
  FileCode2, 
  FileText, 
  GitCommit, 
  Activity, 
  Sliders, 
  Layers
} from 'lucide-react';

export function SeverityBadge({ severity }: { severity: Severity }) {
  const styles: Record<Severity, string> = {
    CRITICAL: 'bg-rose-950/70 text-rose-300 border-rose-500/60 shadow-[0_0_12px_rgba(244,63,94,0.3)] font-bold',
    HIGH: 'bg-amber-950/70 text-amber-300 border-amber-500/60 shadow-[0_0_12px_rgba(245,158,11,0.25)] font-bold',
    MEDIUM: 'bg-yellow-950/60 text-yellow-300 border-yellow-500/50 shadow-[0_0_10px_rgba(234,179,8,0.2)] font-bold',
    LOW: 'bg-sky-950/60 text-sky-300 border-sky-500/50 shadow-[0_0_10px_rgba(14,165,233,0.2)] font-bold',
  };

  return (
    <span className={`inline-flex items-center text-[11px] font-mono font-medium px-2 py-0.5 rounded border ${styles[severity]}`}>
      {severity}
    </span>
  );
}

export function StageBadge({ stage }: { stage: InvestigationStage }) {
  const map: Record<InvestigationStage, { label: string; style: string; dot: string }> = {
    CREATED: {
      label: 'Created',
      style: 'text-slate-600 border-slate-200 bg-slate-50 dark:text-slate-400 dark:border-slate-800 dark:bg-slate-900',
      dot: 'bg-slate-400 dark:bg-slate-500'
    },
    COLLECTING_EVIDENCE: {
      label: 'Collecting Evidence',
      style: 'text-sky-700 border-sky-200 bg-sky-50 dark:text-sky-300 dark:border-sky-800/60 dark:bg-sky-950/40',
      dot: 'bg-sky-500 animate-pulse'
    },
    PLANNING: {
      label: 'Planning',
      style: 'text-indigo-700 border-indigo-200 bg-indigo-50 dark:text-indigo-300 dark:border-indigo-800/60 dark:bg-indigo-950/40',
      dot: 'bg-indigo-500'
    },
    INVESTIGATING: {
      label: 'Investigating',
      style: 'text-blue-700 border-blue-200 bg-blue-50 dark:text-blue-300 dark:border-blue-800/60 dark:bg-blue-950/40',
      dot: 'bg-blue-500 animate-pulse'
    },
    HYPOTHESIS_REVIEW: {
      label: 'Hypothesis Review',
      style: 'text-amber-700 border-amber-200 bg-amber-50 dark:text-amber-300 dark:border-amber-800/60 dark:bg-amber-950/40',
      dot: 'bg-amber-500'
    },
    ROOT_CAUSE_IDENTIFIED: {
      label: 'Root Cause Identified',
      style: 'text-emerald-300 border-emerald-500/50 bg-emerald-950/80 shadow-[0_0_12px_rgba(16,185,129,0.3)] font-bold',
      dot: 'bg-emerald-500'
    },
    RESOLUTION_PLANNED: {
      label: 'Resolution Planned',
      style: 'text-teal-700 border-teal-200 bg-teal-50 dark:text-teal-300 dark:border-teal-800/60 dark:bg-teal-950/40',
      dot: 'bg-teal-500'
    },
    PROMPT_GENERATED: {
      label: 'Prompt Generated',
      style: 'text-violet-700 border-violet-200 bg-violet-50 dark:text-violet-300 dark:border-violet-800/60 dark:bg-violet-950/40',
      dot: 'bg-violet-500'
    },
    AWAITING_AGENT: {
      label: 'Awaiting Agent',
      style: 'text-orange-700 border-orange-200 bg-orange-50 dark:text-orange-300 dark:border-orange-800/60 dark:bg-orange-950/40',
      dot: 'bg-orange-500'
    },
    SANDBOX_RUNNING: {
      label: 'Verifying',
      style: 'text-yellow-700 border-yellow-200 bg-yellow-50 dark:text-yellow-300 dark:border-yellow-800/60 dark:bg-yellow-950/40',
      dot: 'bg-yellow-500 animate-pulse'
    },
    VERIFIED: {
      label: 'Verified Resolution',
      style: 'text-emerald-800 border-emerald-300 bg-emerald-50/80 dark:text-emerald-300 dark:border-emerald-700/60 dark:bg-emerald-950/50',
      dot: 'bg-emerald-500'
    },
    VERIFICATION_FAILED: {
      label: 'Verification Failed',
      style: 'text-rose-700 border-rose-200 bg-rose-50 dark:text-rose-300 dark:border-rose-900/60 dark:bg-rose-950/40',
      dot: 'bg-rose-500'
    },
    BLOCKED: {
      label: 'Blocked',
      style: 'text-rose-800 border-rose-300 bg-rose-100 dark:text-rose-400 dark:border-rose-800 dark:bg-rose-950/60',
      dot: 'bg-rose-500'
    },
    INSUFFICIENT_EVIDENCE: {
      label: 'Insufficient Evidence',
      style: 'text-amber-800 border-amber-300 bg-amber-50 dark:text-amber-300 dark:border-amber-800 dark:bg-amber-950/40',
      dot: 'bg-amber-500 animate-pulse'
    },
    PATCH_READY: {
      label: 'Patch Ready',
      style: 'text-cyan-300 border-cyan-500/50 bg-cyan-950/40 shadow-[0_0_10px_rgba(0,246,255,0.2)]',
      dot: 'bg-cyan-400'
    },
    SANDBOX_QUEUED: {
      label: 'Sandbox Queued',
      style: 'text-amber-300 border-amber-500/50 bg-amber-950/40',
      dot: 'bg-amber-400'
    },
    GATE_CLEARED: {
      label: 'Gate Cleared',
      style: 'text-emerald-300 border-emerald-500/50 bg-emerald-950/40 shadow-[0_0_12px_rgba(16,185,129,0.3)]',
      dot: 'bg-emerald-400'
    },
  };

  const item = map[stage] || {
    label: stage,
    style: 'text-slate-600 border-slate-200 bg-slate-50 dark:text-slate-400 dark:border-slate-800 dark:bg-slate-900',
    dot: 'bg-slate-400'
  };

  return (
    <span className={`inline-flex items-center gap-1.5 text-[11px] font-medium px-2 py-0.5 rounded-md border ${item.style}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${item.dot}`} />
      <span>{item.label}</span>
    </span>
  );
}

export function ConfidenceMeter({ value, confidence }: { value?: number; confidence?: number }) {
  const effectiveVal = value !== undefined ? value : (confidence !== undefined ? confidence : 0);
  const getBadgeStyle = () => {
    if (effectiveVal >= 85) return 'text-emerald-700 border-emerald-200 bg-emerald-50 dark:text-emerald-300 dark:border-emerald-800/60 dark:bg-emerald-950/40';
    if (effectiveVal >= 60) return 'text-amber-800 border-amber-200 bg-amber-50 dark:text-amber-300 dark:border-amber-800/60 dark:bg-amber-950/40';
    return 'text-rose-700 border-rose-200 bg-rose-50 dark:text-rose-300 dark:border-rose-900/60 dark:bg-rose-950/40';
  };

  const getBarColor = () => {
    if (effectiveVal >= 85) return 'bg-emerald-600 dark:bg-emerald-500';
    if (effectiveVal >= 60) return 'bg-amber-500 dark:bg-amber-400';
    return 'bg-rose-500 dark:bg-rose-400';
  };

  return (
    <div className="flex items-center gap-2">
      <div className="w-16 h-1.5 rounded-full bg-slate-200 dark:bg-slate-800 overflow-hidden">
        <div
          className={`h-full transition-all duration-500 ${getBarColor()}`}
          style={{ width: `${Math.min(100, Math.max(0, effectiveVal))}%` }}
        />
      </div>
      <span className={`text-[11px] font-mono font-semibold px-1.5 py-0.5 rounded border ${getBadgeStyle()}`}>
        {effectiveVal}%
      </span>
    </div>
  );
}

export function EvidenceCategoryBadge({ category }: { category: EvidenceCategory }) {
  switch (category) {
    case 'CODE':
      return (
        <span className="inline-flex items-center gap-1 text-[11px] font-medium px-1.5 py-0.5 rounded bg-blue-50 text-blue-700 border border-blue-200 dark:bg-blue-950/40 dark:text-blue-300 dark:border-blue-900/50">
          <FileCode2 size={12} /> Code
        </span>
      );
    case 'AST':
      return (
        <span className="inline-flex items-center gap-1 text-[11px] font-medium px-1.5 py-0.5 rounded bg-cyan-50 text-cyan-700 border border-cyan-200 dark:bg-cyan-950/40 dark:text-cyan-300 dark:border-cyan-900/50">
          <FileCode2 size={12} /> AST Scope
        </span>
      );
    case 'TEST':
      return (
        <span className="inline-flex items-center gap-1 text-[11px] font-medium px-1.5 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200 dark:bg-emerald-950/40 dark:text-emerald-300 dark:border-emerald-900/50">
          <Layers size={12} /> Test Case
        </span>
      );
    case 'REPOSITORY':
      return (
        <span className="inline-flex items-center gap-1 text-[11px] font-medium px-1.5 py-0.5 rounded bg-indigo-50 text-indigo-700 border border-indigo-200 dark:bg-indigo-950/40 dark:text-indigo-300 dark:border-indigo-900/50">
          <Layers size={12} /> Repo Artifact
        </span>
      );
    case 'LOG':
      return (
        <span className="inline-flex items-center gap-1 text-[11px] font-medium px-1.5 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700">
          <FileText size={12} /> Log
        </span>
      );
    case 'GIT':
      return (
        <span className="inline-flex items-center gap-1 text-[11px] font-medium px-1.5 py-0.5 rounded bg-purple-50 text-purple-700 border border-purple-200 dark:bg-purple-950/40 dark:text-purple-300 dark:border-purple-900/50">
          <GitCommit size={12} /> Git Diff
        </span>
      );
    case 'METRIC':
      return (
        <span className="inline-flex items-center gap-1 text-[11px] font-medium px-1.5 py-0.5 rounded bg-amber-50 text-amber-800 border border-amber-200 dark:bg-amber-950/40 dark:text-amber-300 dark:border-amber-900/50">
          <Activity size={12} /> Metric
        </span>
      );
    case 'CONFIG':
      return (
        <span className="inline-flex items-center gap-1 text-[11px] font-medium px-1.5 py-0.5 rounded bg-teal-50 text-teal-700 border border-teal-200 dark:bg-teal-950/40 dark:text-teal-300 dark:border-teal-900/50">
          <Sliders size={12} /> Config
        </span>
      );
    default:
      return (
        <span className="inline-flex items-center gap-1 text-[11px] font-medium px-1.5 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700">
          <Layers size={12} /> {category}
        </span>
      );
  }
}

export function JiraBadge({ ticket }: { ticket: string }) {
  const [copied, setCopied] = React.useState(false);
  const handleCopy = (e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(ticket);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <button
      type="button"
      onClick={handleCopy}
      title="Click to copy Jira ticket"
      className="inline-flex items-center gap-1 text-[11px] font-mono font-medium px-2 py-0.5 rounded bg-blue-50 dark:bg-blue-950/40 text-blue-700 dark:text-blue-300 border border-blue-200 dark:border-blue-800/60 hover:bg-blue-100 dark:hover:bg-blue-900/50 transition-colors"
    >
      <span className="w-1.5 h-1.5 rounded-full bg-blue-500" />
      <span>{ticket}</span>
      {copied ? <span className="text-[9px] text-emerald-600 dark:text-emerald-400">✓</span> : <span className="text-[10px] text-blue-400">↗</span>}
    </button>
  );
}

export function PRBadge({ pr }: { pr: string }) {
  return (
    <span className="inline-flex items-center gap-1 text-[11px] font-mono font-medium px-2 py-0.5 rounded bg-purple-50 dark:bg-purple-950/40 text-purple-700 dark:text-purple-300 border border-purple-200 dark:border-purple-800/60">
      <GitCommit size={11} className="text-purple-500" />
      <span>{pr}</span>
    </span>
  );
}

export function BlastRadiusBadge({ text }: { text: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-[11px] font-medium px-2.5 py-0.5 rounded-full bg-rose-50 dark:bg-rose-950/40 text-rose-700 dark:text-rose-300 border border-rose-200 dark:border-rose-900/60">
      <span className="w-1.5 h-1.5 rounded-full bg-rose-500 animate-pulse" />
      <span className="truncate max-w-[280px] sm:max-w-md">{text}</span>
    </span>
  );
}

export function CanonicalIdBadge({ id }: { id: string }) {
  const [copied, setCopied] = React.useState(false);
  const handleCopy = (e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(id);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <button
      type="button"
      onClick={handleCopy}
      title="Click to copy canonical incident ID"
      className="inline-flex items-center gap-1.5 text-xs font-mono font-bold px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-900 dark:text-white border border-slate-300 dark:border-slate-700 hover:border-indigo-400 dark:hover:border-indigo-500 transition-colors group"
    >
      <span className="text-indigo-600 dark:text-indigo-400">#</span>
      <span>{id}</span>
      {copied ? (
        <span className="text-[10px] text-emerald-600 dark:text-emerald-400">copied</span>
      ) : (
        <span className="text-[10px] text-slate-400 group-hover:text-indigo-500 transition-colors">⧉</span>
      )}
    </button>
  );
}
