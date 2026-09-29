import React, { useState } from 'react';
import { 
  Terminal, 
  Search, 
  Wrench, 
  CheckCircle2, 
  ChevronDown, 
  ChevronUp, 
  HelpCircle,
  ArrowRight,
  Sparkles,
  ShieldCheck,
  Zap
} from 'lucide-react';

interface HowItWorksBannerProps {
  defaultExpanded?: boolean;
}

export function HowItWorksBanner({ defaultExpanded = true }: HowItWorksBannerProps) {
  const [isExpanded, setIsExpanded] = useState(() => {
    const saved = localStorage.getItem('oracle_guide_expanded');
    return saved !== null ? saved === 'true' : defaultExpanded;
  });

  const toggle = () => {
    setIsExpanded((prev) => {
      const next = !prev;
      localStorage.setItem('oracle_guide_expanded', String(next));
      return next;
    });
  };

  const steps = [
    {
      num: '01',
      title: 'Ingest Incident',
      desc: 'Ingests production error logs, APM traces, and deployment alerts.',
      icon: Terminal,
      color: 'text-sky-600 dark:text-sky-400',
      border: 'border-sky-200 dark:border-sky-800/60 bg-sky-50/50 dark:bg-sky-950/30',
      badge: 'Step 1'
    },
    {
      num: '02',
      title: 'Isolate Root Cause',
      desc: 'Correlates git diffs, code AST, and telemetry to pinpoint the exact broken line.',
      icon: Search,
      color: 'text-indigo-600 dark:text-indigo-400',
      border: 'border-indigo-200 dark:border-indigo-800/60 bg-indigo-50/50 dark:bg-indigo-950/30',
      badge: 'Step 2'
    },
    {
      num: '03',
      title: 'Formulate Code Fix',
      desc: 'Generates defensive code steps and ready-to-run prompts for coding agents.',
      icon: Wrench,
      color: 'text-amber-600 dark:text-amber-400',
      border: 'border-amber-200 dark:border-amber-800/60 bg-amber-50/50 dark:bg-amber-950/30',
      badge: 'Step 3'
    },
    {
      num: '04',
      title: 'Verify in Sandbox',
      desc: 'Executes simulated regression tests in an isolated container to guarantee safety.',
      icon: CheckCircle2,
      color: 'text-emerald-600 dark:text-emerald-400',
      border: 'border-emerald-200 dark:border-emerald-800/60 bg-emerald-50/50 dark:bg-emerald-950/30',
      badge: 'Step 4'
    }
  ];

  return (
    <div className="border border-indigo-200/80 dark:border-indigo-900/60 bg-gradient-to-r from-indigo-50/70 via-white to-slate-50 dark:from-indigo-950/30 dark:via-slate-900 dark:to-slate-900 rounded-xl overflow-hidden shadow-2xs transition-all">
      {/* Header Bar */}
      <div className="p-4 flex items-center justify-between gap-3 border-b border-indigo-100 dark:border-indigo-950/60">
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 rounded-lg bg-indigo-600 text-white shadow-xs">
            <Sparkles size={14} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-xs font-bold uppercase tracking-wider text-slate-900 dark:text-white">
                How ORACLE Works
              </h2>
              <span className="text-[10px] font-medium px-2 py-0.5 rounded-full bg-indigo-100 dark:bg-indigo-900/60 text-indigo-700 dark:text-indigo-300">
                New User Guide
              </span>
            </div>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
              ORACLE acts as an autonomous incident doctor: it diagnoses production outages, pinpoints the broken code lines, and verifies the fix before deployment.
            </p>
          </div>
        </div>

        <button
          type="button"
          onClick={toggle}
          className="flex items-center gap-1 px-2.5 py-1 text-xs font-medium rounded-lg text-slate-600 dark:text-slate-300 hover:bg-slate-200/60 dark:hover:bg-slate-800 transition-colors shrink-0"
        >
          <span>{isExpanded ? 'Hide Workflow' : 'Show Workflow'}</span>
          {isExpanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
        </button>
      </div>

      {/* Expandable 4-Step Diagram */}
      {isExpanded && (
        <div className="p-4 bg-white/60 dark:bg-slate-900/40">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 relative">
            {steps.map((step, idx) => {
              const Icon = step.icon;
              return (
                <div
                  key={step.num}
                  className={`p-3.5 rounded-xl border ${step.border} flex flex-col justify-between transition-all`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-[10px] font-mono font-bold text-slate-400 dark:text-slate-500">
                      {step.badge}
                    </span>
                    <Icon size={16} className={step.color} />
                  </div>

                  <div className="space-y-1">
                    <h3 className="text-xs font-bold text-slate-900 dark:text-white">
                      {step.title}
                    </h3>
                    <p className="text-[11px] text-slate-500 dark:text-slate-400 leading-relaxed">
                      {step.desc}
                    </p>
                  </div>

                  <div className="mt-2.5 pt-2 border-t border-slate-200/60 dark:border-slate-800/60 text-[10px] font-mono text-slate-400 flex items-center justify-between">
                    <span>Deterministic Phase</span>
                    <span>✓ Automated</span>
                  </div>
                </div>
              );
            })}
          </div>

          <div className="mt-3 pt-3 border-t border-slate-100 dark:border-slate-800/80 flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500 dark:text-slate-400">
            <div className="flex items-center gap-2">
              <ShieldCheck size={14} className="text-emerald-600 dark:text-emerald-400 shrink-0" />
              <span><strong>Zero Hallucination Guarantee:</strong> Root-causes are accepted only if supported by real logs and git commits without contradictions.</span>
            </div>
            <span className="text-[11px] text-indigo-600 dark:text-indigo-400 font-medium">
              Ready to use • Select an incident below to begin
            </span>
          </div>
        </div>
      )}
    </div>
  );
}
