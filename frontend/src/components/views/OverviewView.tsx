import React, { useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { audioFx } from '../../lib/audio';
import { 
  Activity, 
  Terminal, 
  Layers, 
  CheckCircle2, 
  FolderGit2, 
  ArrowRight, 
  AlertTriangle,
  Clock,
  ShieldCheck,
  ChevronRight,
  TrendingUp,
  FileCheck2,
  GitBranch,
  Lock,
  Play,
  Check,
  XCircle,
  Cpu,
  ShieldAlert,
  Sparkles,
  HelpCircle,
  Zap,
  Flame,
  Search,
  Code2,
  RefreshCw,
  Box,
  Fingerprint
} from 'lucide-react';
import { IncidentInvestigation, SystemMetrics } from '../../types/oracle';
import { 
  SeverityBadge, 
  StageBadge, 
  ConfidenceMeter 
} from '../common/Badges';

interface OverviewViewProps {
  investigations: IncidentInvestigation[];
  metrics: SystemMetrics;
  onOpenWorkspace: (incident: IncidentInvestigation) => void;
  onStartNew: () => void;
  onNavigate: (tab: string) => void;
}

export function OverviewView({
  investigations,
  metrics,
  onOpenWorkspace,
  onStartNew,
  onNavigate,
}: OverviewViewProps) {
  const [selectedPipelineStep, setSelectedPipelineStep] = useState<number>(0);
  const canonicalInc = investigations.find((i) => i.id === 'INC-1042') || investigations[0];

  const pipelineSteps = [
    {
      num: 1,
      name: 'Alert Ingestion',
      icon: AlertTriangle,
      tag: 'Step 1: Detect',
      color: 'from-amber-500/20 to-orange-500/10 border-amber-500/30 text-amber-300',
      headline: 'Telemetry & Anomaly Ingestion',
      desc: 'ORACLE listens to live webhooks from Sentry, Datadog, CloudWatch, and PagerDuty. Upon detecting an anomaly (e.g. 500 error spike), an investigation workspace is automatically instantiated with full context.',
      metric: '0.4s Ingestion Latency',
      actionTab: 'workspace',
      actionLabel: 'View Active Incident'
    },
    {
      num: 2,
      name: 'Multi-Modal Evidence',
      icon: Search,
      tag: 'Step 2: Correlate',
      color: 'from-sky-500/20 to-blue-500/10 border-sky-500/30 text-sky-300',
      headline: 'Automated Forensic Correlation',
      desc: 'The evidence engine scrapes container logs, git diffs from the last 24h, database slow queries, and eBPF network metrics to assemble a unified incident timeline.',
      metric: '12,400 Logs Correlated',
      actionTab: 'evidence',
      actionLabel: 'Inspect Evidence Graph'
    },
    {
      num: 3,
      name: 'Root Cause Hypothesis',
      icon: Cpu,
      tag: 'Step 3: Hypothesize',
      color: 'from-indigo-500/20 to-violet-500/10 border-indigo-500/30 text-indigo-300',
      headline: 'AI-Ranked Causal Isolation',
      desc: 'ORACLE formulates competing hypotheses, tests them against observed traces, and isolates the culprit commit (e.g. 8f2a41d) with mathematical confidence scores.',
      metric: '94.2% Confidence Score',
      actionTab: 'workspace',
      actionLabel: 'Review Hypotheses'
    },
    {
      num: 4,
      name: 'Autonomous Patch Synthesis',
      icon: Code2,
      tag: 'Step 4: Remediate',
      color: 'from-cyan-500/20 to-teal-500/10 border-cyan-500/30 text-cyan-300',
      headline: 'Zero-Shot Code Generation',
      desc: 'The code intelligence engine writes a surgical, minimal diff correcting the flaw (adding defensive null-checks and idempotency fallbacks) along with unit regression tests.',
      metric: 'Minimal 14-Line Diff',
      actionTab: 'resolutions',
      actionLabel: 'Inspect Synthesized Patch'
    },
    {
      num: 5,
      name: 'Zero-Trust Sandbox Replay',
      icon: ShieldCheck,
      tag: 'Step 5: Verify',
      color: 'from-emerald-500/20 to-green-500/10 border-emerald-500/30 text-emerald-300',
      headline: 'Deterministic Proof Before Deployment',
      desc: 'Never confuse a proposed fix with a verified fix. The patch is loaded into an isolated Docker sandbox where 500+ production-like traffic payloads are replayed to prove zero regressions.',
      metric: '18.42s Sandbox Pass Time',
      actionTab: 'verification',
      actionLabel: 'Open Sandbox Replay'
    }
  ];

  const currentStepData = pipelineSteps[selectedPipelineStep];

  const verificationQueue = [
    {
      id: 'INC-1042',
      title: 'Payment API returning 500 errors',
      action: 'Sandbox Replay',
      status: 'VERIFIED',
      service: 'payment-api',
      duration: '18.42s',
      statusColor: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30',
      targetInc: canonicalInc
    },
    {
      id: 'INC-1041',
      title: 'Kafka Consumer Lag Spike in Order Processor',
      action: 'Sandbox Replay',
      status: 'VERIFYING',
      service: 'order-processor',
      duration: '0m 42s',
      statusColor: 'text-sky-400 bg-sky-500/10 border-sky-500/30',
      targetInc: investigations.find(i => i.id === 'INC-1041') || canonicalInc
    },
    {
      id: 'INC-1038',
      title: 'Cart Checkout 504 Gateway Timeout',
      action: 'Safety Gate',
      status: 'BLOCKED',
      service: 'cart-service',
      duration: '14.12s',
      statusColor: 'text-rose-400 bg-rose-500/10 border-rose-500/30',
      targetInc: investigations.find(i => i.id === 'INC-1038') || canonicalInc
    }
  ];

  return (
    <div className="p-6 lg:p-8 max-w-7xl mx-auto space-y-8 text-slate-100 font-sans antialiased">
      {/* Living 3D Topology System Map */}
      <motion.div 
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.35 }}
        className="p-6 rounded-2xl border border-neutral-200/80 dark:border-neutral-800 bg-white dark:bg-neutral-950 shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-6"
      >
        <div className="space-y-1.5">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            <span className="text-xs font-semibold font-mono text-emerald-600 dark:text-emerald-400">
              REAL-TIME CONTROL PLANE
            </span>
            <span className="text-neutral-300 dark:text-neutral-700">|</span>
            <span className="text-xs text-neutral-500 font-mono">
              FastAPI Persistent Backend Active
            </span>
          </div>
          <h1 className="text-2xl font-extrabold tracking-tight font-heading text-neutral-950 dark:text-white">
            Engineering Investigation & Resolution Command Center
          </h1>
          <p className="text-xs sm:text-sm text-neutral-600 dark:text-neutral-400 max-w-2xl leading-relaxed">
            Multi-modal forensic correlation, zero-shot AST patch generation, and zero-trust Docker sandbox verification.
          </p>
        </div>

        <div className="flex items-center gap-2.5 shrink-0">
          <button
            onClick={() => onNavigate('landing')}
            className="flex items-center gap-1.5 px-3 py-2 rounded-xl border border-neutral-200 dark:border-neutral-800 hover:bg-neutral-100 dark:hover:bg-neutral-900 text-xs font-semibold text-neutral-700 dark:text-neutral-300 transition-colors"
          >
            <span>← Landing Page</span>
          </button>
          <button
            onClick={onStartNew}
            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-neutral-900 hover:bg-neutral-800 dark:bg-white dark:text-neutral-900 dark:hover:bg-neutral-200 text-white font-bold text-xs shadow-sm transition-all"
          >
            <Terminal size={14} />
            <span>+ Ingest Incident</span>
          </button>
        </div>
      </motion.div>

      {/* Header & Quick Action Hub */}
      <motion.div 
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay: 0.05 }}
        className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-white/10"
      >
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight font-heading text-white">
              Autonomous Intelligence Control Plane
            </h1>
            <span className="flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-mono font-medium border bg-emerald-500/10 text-emerald-300 border-emerald-500/30 shadow-[0_0_12px_rgba(16,185,129,0.2)]">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              LIVE TELEMETRY
            </span>
          </div>
          <p className="text-sm text-slate-400 mt-1 max-w-2xl font-normal leading-relaxed">
            Evidence-driven root-cause isolation, automated patch synthesis, and zero-trust sandbox verification for mission-critical software.
          </p>
        </div>

        <div className="flex items-center gap-3 shrink-0">
          {canonicalInc && (
            <button
              onClick={() => {
                audioFx.click();
                onOpenWorkspace(canonicalInc);
              }}
              className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-sky-500/10 hover:bg-sky-500/20 text-sky-300 border border-sky-500/30 font-semibold text-xs tracking-tight transition-all duration-200 hover:shadow-[0_0_15px_rgba(56,189,248,0.25)] hover:-translate-y-0.5"
            >
              <FolderGit2 size={15} />
              <span>Explore INC-1042</span>
            </button>
          )}
          <button
            onClick={() => {
              audioFx.click();
              onStartNew();
            }}
            className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-gradient-to-r from-sky-500 to-indigo-600 hover:from-sky-400 hover:to-indigo-500 text-white font-bold text-xs tracking-tight transition-all duration-200 shadow-[0_0_20px_rgba(56,189,248,0.3)] hover:-translate-y-0.5"
          >
            <Terminal size={15} />
            <span>+ Ingest Incident</span>
          </button>
        </div>
      </motion.div>

      {/* ── INTERACTIVE END-TO-END INVESTIGATION PIPELINE ── */}
      <motion.div 
        initial={{ opacity: 0, y: 15 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay: 0.1 }}
        className="glass-panel-elevated p-6 rounded-2xl relative overflow-hidden"
      >
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-5">
          <div className="flex items-center gap-2.5">
            <div className="w-7 h-7 rounded-lg bg-indigo-500/20 border border-indigo-500/30 flex items-center justify-center text-indigo-400">
              <Sparkles size={16} />
            </div>
            <div>
              <h2 className="text-base font-bold text-white tracking-tight font-heading">
                End-to-End Investigation & Resolution Flow
              </h2>
              <p className="text-xs text-slate-400">
                Click any step to understand how ORACLE autonomously moves from alert to verified deployment.
              </p>
            </div>
          </div>
          <span className="text-xs font-mono text-cyan-400 bg-cyan-950/60 border border-cyan-800/60 px-3 py-1 rounded-full self-start sm:self-auto">
            Interactive Walkthrough
          </span>
        </div>

        {/* Pipeline Step Navigator */}
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 mb-6">
          {pipelineSteps.map((step, idx) => {
            const Icon = step.icon;
            const isSelected = selectedPipelineStep === idx;
            return (
              <button
                key={step.num}
                onClick={() => {
                  audioFx.click();
                  setSelectedPipelineStep(idx);
                }}
                className={`flex flex-col items-start p-3.5 rounded-xl border text-left transition-all duration-200 relative ${
                  isSelected 
                    ? 'bg-slate-800/90 border-sky-400 shadow-[0_0_20px_rgba(56,189,248,0.25)] -translate-y-1' 
                    : 'bg-slate-900/40 border-white/10 hover:border-white/20 hover:bg-slate-800/40'
                }`}
              >
                <div className="flex items-center justify-between w-full mb-2">
                  <div className={`w-6 h-6 rounded-md flex items-center justify-center ${isSelected ? 'bg-sky-500 text-white' : 'bg-slate-800 text-slate-400'}`}>
                    <Icon size={13} />
                  </div>
                  <span className="text-[10px] font-mono text-slate-400 font-bold">0{step.num}</span>
                </div>
                <span className={`text-xs font-bold font-heading ${isSelected ? 'text-white' : 'text-slate-300'}`}>
                  {step.name}
                </span>
                <span className="text-[10px] text-slate-400 mt-0.5 truncate w-full">
                  {step.tag}
                </span>
                {isSelected && (
                  <motion.div 
                    layoutId="activePipelineIndicator"
                    className="absolute bottom-0 left-0 right-0 h-1 bg-gradient-to-r from-sky-400 to-indigo-500 rounded-b-xl"
                  />
                )}
              </button>
            );
          })}
        </div>

        {/* Selected Step Deep Dive Card */}
        <AnimatePresence mode="wait">
          <motion.div
            key={currentStepData.num}
            initial={{ opacity: 0, x: -10 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: 10 }}
            transition={{ duration: 0.2 }}
            className="p-5 rounded-xl bg-slate-900/80 border border-white/10 flex flex-col md:flex-row items-start md:items-center justify-between gap-5"
          >
            <div className="space-y-2 max-w-3xl">
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono font-bold px-2.5 py-0.5 rounded bg-sky-500/20 text-sky-300 border border-sky-500/30">
                  {currentStepData.tag}
                </span>
                <h3 className="text-base font-bold text-white font-heading">
                  {currentStepData.headline}
                </h3>
              </div>
              <p className="text-sm text-slate-300 leading-relaxed font-normal">
                {currentStepData.desc}
              </p>
              <div className="flex items-center gap-3 pt-1">
                <span className="text-xs font-mono text-emerald-400 bg-emerald-500/10 px-2.5 py-0.5 rounded border border-emerald-500/20">
                  Proof: {currentStepData.metric}
                </span>
              </div>
            </div>

            <button
              onClick={() => {
                audioFx.click();
                if (currentStepData.actionTab === 'workspace' && canonicalInc) {
                  onOpenWorkspace(canonicalInc);
                } else {
                  onNavigate(currentStepData.actionTab);
                }
              }}
              className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-sky-500 hover:bg-sky-400 text-slate-950 font-bold text-xs shrink-0 transition-all hover:shadow-[0_0_15px_rgba(56,189,248,0.4)]"
            >
              <span>{currentStepData.actionLabel}</span>
              <ArrowRight size={14} />
            </button>
          </motion.div>
        </AnimatePresence>
      </motion.div>

      {/* ── SYSTEM OPERATIONAL METRICS ── */}
      <motion.div 
        initial={{ opacity: 0, y: 15 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay: 0.15 }}
        className="space-y-3"
      >
        <div className="flex items-center justify-between">
          <h2 className="text-xs font-bold uppercase tracking-wider text-slate-400 font-mono">
            System Operational Telemetry
          </h2>
          <span className="text-xs font-mono text-slate-500">Continuous Evaluation</span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4">
          <div className="glass-card p-4 border border-white/10 hover:border-sky-500/30">
            <span className="text-xs font-medium text-slate-400">Active Incidents</span>
            <div className="flex items-baseline gap-2 mt-2">
              <span className="text-3xl font-extrabold text-white font-mono">{metrics.activeInvestigations}</span>
              <span className="text-[11px] text-amber-400 font-mono font-medium">In Progress</span>
            </div>
          </div>

          <div className="glass-card p-4 border border-white/10 hover:border-emerald-500/30">
            <span className="text-xs font-medium text-slate-400">MTTI (Mean Time to Isolate)</span>
            <div className="flex items-baseline gap-2 mt-2">
              <span className="text-3xl font-extrabold text-emerald-400 font-mono">2.4m</span>
              <span className="text-[11px] text-slate-400 font-mono">vs 45m human</span>
            </div>
          </div>

          <div className="glass-card p-4 border border-white/10 hover:border-sky-500/30">
            <span className="text-xs font-medium text-slate-400">Sandbox Verification Rate</span>
            <div className="flex items-baseline gap-2 mt-2">
              <span className="text-3xl font-extrabold text-sky-400 font-mono">99.4%</span>
              <span className="text-[11px] text-emerald-400 font-mono">0 false-positives</span>
            </div>
          </div>

          <div className="glass-card p-4 border border-white/10 hover:border-indigo-500/30">
            <span className="text-xs font-medium text-slate-400">Autonomous Patches Synthesized</span>
            <div className="flex items-baseline gap-2 mt-2">
              <span className="text-3xl font-extrabold text-indigo-300 font-mono">{metrics.verifiedResolutions || 142}</span>
              <span className="text-[11px] text-indigo-400 font-mono">100% AST clean</span>
            </div>
          </div>

          <div className="glass-card p-4 border border-white/10 hover:border-teal-500/30">
            <span className="text-xs font-medium text-slate-400">Zero-Trust Gate Status</span>
            <div className="flex items-baseline gap-2 mt-2">
              <span className="text-3xl font-extrabold text-teal-300 font-mono">CLEARED</span>
              <span className="text-[11px] text-teal-400 font-mono">Replay Green</span>
            </div>
          </div>
        </div>
      </motion.div>

      {/* ── CANONICAL INCIDENT SPOTLIGHT (INC-1042) ── */}
      {canonicalInc && (
        <motion.div 
          initial={{ opacity: 0, y: 15 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.2 }}
          className="glass-panel p-6 rounded-2xl border border-sky-500/30 bg-gradient-to-r from-slate-900/90 via-slate-900/60 to-indigo-950/30 shadow-[0_0_30px_rgba(56,189,248,0.1)] relative"
        >
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
            <div className="space-y-3 max-w-3xl">
              <div className="flex flex-wrap items-center gap-2.5">
                <span className="px-2.5 py-0.5 rounded font-mono text-xs font-bold bg-rose-500/20 text-rose-300 border border-rose-500/30">
                  HIGH SEVERITY
                </span>
                <span className="px-2.5 py-0.5 rounded font-mono text-xs font-bold bg-sky-500/20 text-sky-300 border border-sky-500/30">
                  {canonicalInc.id}
                </span>
                <span className="text-xs text-slate-400 font-mono">
                  Service: <strong className="text-white">{canonicalInc.service}</strong>
                </span>
                <span className="text-xs text-slate-400 font-mono">
                  Env: <strong className="text-white">{canonicalInc.environment}</strong>
                </span>
              </div>

              <h2 className="text-xl font-extrabold text-white font-heading tracking-tight">
                {canonicalInc.title}
              </h2>

              <p className="text-sm text-slate-300 font-normal leading-relaxed">
                Stripe webhook integration crashed with an unhandled NullPointerException on idempotency token verification.
                ORACLE isolated the issue to commit <span className="font-mono text-cyan-300 bg-cyan-950/60 px-1.5 py-0.5 rounded">8f2a41d</span>, synthesized a 14-line defensive patch, and validated it inside an isolated Docker sandbox replay with 0 regressions.
              </p>

              <div className="flex flex-wrap items-center gap-4 text-xs font-mono pt-1 text-slate-400">
                <div className="flex items-center gap-1.5 text-emerald-400">
                  <CheckCircle2 size={15} />
                  <span>Sandbox Proof Verified (18.42s)</span>
                </div>
                <div className="flex items-center gap-1.5 text-sky-400">
                  <GitBranch size={15} />
                  <span>PR #142 Ready to Merge</span>
                </div>
                <div className="flex items-center gap-1.5 text-amber-400">
                  <Flame size={15} />
                  <span>$42.5k/min GMV Protected</span>
                </div>
              </div>
            </div>

            <div className="flex flex-col sm:flex-row lg:flex-col gap-3 shrink-0">
              <button
                onClick={() => {
                  audioFx.click();
                  onOpenWorkspace(canonicalInc);
                }}
                className="flex items-center justify-center gap-2 px-5 py-3 rounded-xl bg-gradient-to-r from-sky-500 to-indigo-600 hover:from-sky-400 hover:to-indigo-500 text-white font-bold text-xs tracking-tight transition-all duration-200 shadow-[0_0_20px_rgba(56,189,248,0.35)] hover:-translate-y-0.5"
              >
                <span>Open Incident Workspace</span>
                <ArrowRight size={15} />
              </button>
              <button
                onClick={() => {
                  audioFx.click();
                  onNavigate('verification');
                }}
                className="flex items-center justify-center gap-2 px-5 py-2.5 rounded-xl bg-slate-800/80 hover:bg-slate-800 text-slate-200 border border-white/10 hover:border-sky-500/40 font-semibold text-xs tracking-tight transition-all"
              >
                <ShieldCheck size={15} className="text-emerald-400" />
                <span>View Verification Logs</span>
              </button>
            </div>
          </div>
        </motion.div>
      )}

      {/* ── DUAL GRID: VERIFICATION QUEUE & ACTIVE INCIDENTS ── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Verification Queue (1 col) */}
        <motion.div 
          initial={{ opacity: 0, y: 15 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.25 }}
          className="glass-card p-5 border border-white/10 space-y-4"
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <ShieldCheck size={16} className="text-sky-400" />
              <h3 className="text-sm font-bold text-white font-heading">
                Sandbox Verification Queue
              </h3>
            </div>
            <span className="text-[11px] font-mono text-slate-400">Zero-Trust Gate</span>
          </div>

          <p className="text-xs text-slate-400 leading-normal">
            Every remediation patch must clear the automated container sandbox before merging.
          </p>

          <div className="space-y-2.5">
            {verificationQueue.map((item) => (
              <div 
                key={item.id}
                onClick={() => {
                  audioFx.click();
                  if (item.targetInc) onOpenWorkspace(item.targetInc);
                }}
                className="p-3 rounded-xl bg-slate-900/60 border border-white/5 hover:border-sky-500/30 transition-all cursor-pointer hover:bg-slate-800/50"
              >
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-xs font-mono font-bold text-sky-300">{item.id}</span>
                  <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${item.statusColor}`}>
                    {item.status}
                  </span>
                </div>
                <h4 className="text-xs font-semibold text-slate-200 truncate">{item.title}</h4>
                <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 mt-2 pt-2 border-t border-white/5">
                  <span>{item.service}</span>
                  <span>{item.duration}</span>
                </div>
              </div>
            ))}
          </div>
        </motion.div>

        {/* Active Investigations Table (2 cols) */}
        <motion.div 
          initial={{ opacity: 0, y: 15 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.3 }}
          className="lg:col-span-2 glass-card p-5 border border-white/10 space-y-4"
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Layers size={16} className="text-indigo-400" />
              <h3 className="text-sm font-bold text-white font-heading">
                Active Forensic Investigations
              </h3>
            </div>
            <span className="text-xs font-mono text-slate-400">
              {investigations.length} Active Records
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-white/10 text-slate-400 font-mono text-[11px]">
                  <th className="pb-2.5 font-semibold">Incident</th>
                  <th className="pb-2.5 font-semibold">Service</th>
                  <th className="pb-2.5 font-semibold">Severity</th>
                  <th className="pb-2.5 font-semibold">Stage</th>
                  <th className="pb-2.5 font-semibold text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {investigations.map((inc) => (
                  <tr 
                    key={inc.id}
                    onClick={() => {
                      audioFx.click();
                      onOpenWorkspace(inc);
                    }}
                    className="hover:bg-slate-800/50 cursor-pointer transition-colors group"
                  >
                    <td className="py-3 pr-3">
                      <div className="font-mono font-bold text-sky-300 group-hover:text-sky-200">{inc.id}</div>
                      <div className="text-slate-300 truncate max-w-xs">{inc.title}</div>
                    </td>
                    <td className="py-3 pr-3 font-mono text-slate-400">
                      {inc.service}
                    </td>
                    <td className="py-3 pr-3">
                      <SeverityBadge severity={inc.severity} />
                    </td>
                    <td className="py-3 pr-3">
                      <StageBadge stage={inc.stage} />
                    </td>
                    <td className="py-3 text-right">
                      <button className="px-2.5 py-1 rounded bg-slate-800 group-hover:bg-sky-500 group-hover:text-slate-950 text-slate-300 font-semibold text-[11px] transition-colors">
                        Investigate &rarr;
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </motion.div>
      </div>
    </div>
  );
}
