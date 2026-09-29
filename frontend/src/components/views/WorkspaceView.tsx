import { motion, AnimatePresence } from 'motion/react';
import { audioFx } from '../../lib/audio';
import React, { useState, useEffect } from 'react';
import { 
  IncidentInvestigation, 
  InvestigationStage, 
  EvidenceItem,
  Hypothesis,
  AgentTargetFormat 
} from '../../types/oracle';
import { 
  SeverityBadge, 
  StageBadge, 
  ConfidenceMeter, 
  EvidenceCategoryBadge,
  JiraBadge,
  PRBadge,
  BlastRadiusBadge,
  CanonicalIdBadge
} from '../common/Badges';
import { TopologyGraph } from '../common/TopologyGraph';
import { 
  CheckCircle2, 
  ShieldCheck, 
  ArrowRight, 
  FileCode2, 
  FolderGit2, 
  AlertTriangle, 
  Copy, 
  Check, 
  Terminal, 
  ChevronRight,
  Info,
  Network,
  Play,
  FileText,
  Filter,
  Sparkles,
  RefreshCw,
  Search,
  Wrench,
  Lock,
  Shield,
  Award,
  GitBranch,
  Cpu,
  Code2,
  Clock,
  Download,
  ExternalLink,
  Layers,
  FileCheck,
  XCircle,
  HelpCircle
} from 'lucide-react';
import { generateAgentTask } from '../../lib/api/agents';

interface WorkspaceViewProps {
  investigation: IncidentInvestigation;
  onNavigateTab?: (tab: string) => void;
  onRunVerification: (outcome?: 'VERIFIED' | 'FAILED') => Promise<void>;
}

export type WorkspaceSection = 
  | 'OVERVIEW'
  | 'TIMELINE'
  | 'EVIDENCE' 
  | 'HYPOTHESES' 
  | 'ROOT_CAUSE' 
  | 'RESOLUTION' 
  | 'AGENT_TASK'
  | 'VERIFICATION';

export function WorkspaceView({ 
  investigation, 
  onNavigateTab, 
  onRunVerification 
}: WorkspaceViewProps) {
  const [activeSection, setActiveSection] = useState<WorkspaceSection>('OVERVIEW');
  const [selectedEvidence, setSelectedEvidence] = useState<EvidenceItem | null>(investigation.evidence[0] || null);
  const [evidenceFilter, setEvidenceFilter] = useState<string>('ALL');
  const [evidenceSearch, setEvidenceSearch] = useState<string>('');
  
  // Agent Task generator state
  const [agentFormat, setAgentFormat] = useState<AgentTargetFormat>('Claude Code');
  const [copiedTask, setCopiedTask] = useState(false);
  
  // Sandbox Verification states
  const [verificationSimState, setVerificationSimState] = useState<'PASS' | 'FAIL'>('PASS');
  const [isRunningVerification, setIsRunningVerification] = useState(false);
  const [verificationSuccessToast, setVerificationSuccessToast] = useState(false);
  const [sandboxArtifactTab, setSandboxArtifactTab] = useState<'OUTPUT' | 'TEST_CODE' | 'DIFF' | 'CERTIFICATE'>('OUTPUT');
  const [replayPhase, setReplayPhase] = useState<number>(0);

  // Sync selected evidence when investigation changes
  useEffect(() => {
    if (investigation.evidence && investigation.evidence.length > 0) {
      setSelectedEvidence(investigation.evidence[0]);
    } else {
      setSelectedEvidence(null);
    }
  }, [investigation.id]);

  // Derived state machine (Section 5 & 24)
  const STATE_STAGES: { key: string; label: string; minIndex: number }[] = [
    { key: 'EVIDENCE', label: 'Evidence', minIndex: 1 },
    { key: 'PLANNING', label: 'Planning', minIndex: 2 },
    { key: 'INVESTIGATION', label: 'Investigation', minIndex: 3 },
    { key: 'ROOT_CAUSE', label: 'Root Cause', minIndex: 5 },
    { key: 'RESOLUTION', label: 'Resolution', minIndex: 6 },
    { key: 'SANDBOX', label: 'Sandbox Verification', minIndex: 10 },
    { key: 'DEPLOYMENT', label: 'Deployment Gate', minIndex: 13 },
  ];

  const STAGE_ORDER: Record<InvestigationStage, number> = {
    'CREATED': 0,
    'COLLECTING_EVIDENCE': 1,
    'PLANNING': 2,
    'INVESTIGATING': 3,
    'HYPOTHESIS_REVIEW': 4,
    'ROOT_CAUSE_IDENTIFIED': 5,
    'RESOLUTION_PLANNED': 6,
    'PROMPT_GENERATED': 7,
    'AWAITING_AGENT': 8,
    'PATCH_READY': 9,
    'SANDBOX_QUEUED': 10,
    'SANDBOX_RUNNING': 11,
    'VERIFICATION_FAILED': 11,
    'VERIFIED': 12,
    'GATE_CLEARED': 13,
    'BLOCKED': 11,
    'INSUFFICIENT_EVIDENCE': 3,
  };

  const currentStageIndex = STAGE_ORDER[investigation.stage] || 5;

  // Filtered evidence items
  const filteredEvidence = investigation.evidence.filter((item) => {
    const matchesFilter = evidenceFilter === 'ALL' || item.category.toUpperCase() === evidenceFilter;
    const matchesSearch = evidenceSearch === '' || 
      item.summary.toLowerCase().includes(evidenceSearch.toLowerCase()) ||
      item.source.toLowerCase().includes(evidenceSearch.toLowerCase()) ||
      item.id.toLowerCase().includes(evidenceSearch.toLowerCase());
    return matchesFilter && matchesSearch;
  });

  // Agent task generation text
  const agentTaskPrompt = `You are working on production incident ${investigation.id}.

INCIDENT:
${investigation.title}
Target Service: ${investigation.service} | Severity: ${investigation.severity} | Env: ${investigation.environment}

ROOT CAUSE:
${investigation.rootCause ? investigation.rootCause.title : 'Redis cache-key namespace mismatch'} (Confidence: ${investigation.confidence}%)
Reasoning Chain:
${investigation.rootCause?.explanationChain.map((e, idx) => `  ${idx + 1}. ${e}`).join('\n') || '  1. Production error\n  2. Redis lookup misses\n  3. Git diff altered key namespace'}

EMPIRICAL EVIDENCE:
${investigation.evidence.map((e) => `[${e.id}] ${e.source} (Line ${e.line || 'N/A'}): ${e.summary}`).join('\n')}

AFFECTED FILES:
${investigation.resolution?.affectedFiles.map((f) => `- ${f}`).join('\n') || '- src/customer/repository.py\n- src/payment/payment_service.py'}

REQUIRED CHANGES:
${investigation.resolution?.steps.map((s, i) => `${i + 1}. ${s}`).join('\n') || '1. Support legacy namespace.\n2. Preserve new namespace.\n3. Add regression test.\n4. Validate cache miss behavior.'}

CONSTRAINTS:
- Do NOT modify unrelated components outside the affected files list.
- Ensure strict backwards compatibility for active customer sessions.
- Do NOT alter database schema or external network pooling contracts.
- If your independent code inspection contradicts this root cause, STOP and flag the discrepancy instead of applying incorrect changes.

VERIFICATION:
The original failure must no longer reproduce.
Run the existing regression suite (842 tests).
Report all changed files and test results for ORACLE Sandbox Verification.`;

  const copyTaskPrompt = () => {
    navigator.clipboard.writeText(agentTaskPrompt);
    setCopiedTask(true);
    setTimeout(() => setCopiedTask(false), 2000);
  };

  const downloadTaskPrompt = () => {
    const blob = new Blob([agentTaskPrompt], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `ORACLE-TASK-${investigation.id}.txt`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const downloadTerminalLogs = () => {
    const text = investigation.verification?.terminalOutput || 'Pytest session logs';
    const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `ORACLE-VERIFY-${investigation.id}.log`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const handleExecuteVerification = async () => {
    setIsRunningVerification(true);
    setReplayPhase(1);
    setTimeout(() => setReplayPhase(2), 350);
    setTimeout(() => setReplayPhase(3), 750);
    setTimeout(() => setReplayPhase(4), 1200);
    try {
      await onRunVerification(verificationSimState === 'PASS' ? 'VERIFIED' : 'FAILED');
      setTimeout(() => {
        setReplayPhase(5);
        setVerificationSuccessToast(true);
        setTimeout(() => setVerificationSuccessToast(false), 4000);
      }, 1600);
    } catch (e) {
      console.error(e);
    } finally {
      setTimeout(() => setIsRunningVerification(false), 1900);
    }
  };

  const WORKSPACE_SECTIONS = [
    { id: 'OVERVIEW' as const, label: 'Overview', icon: Search },
    { id: 'TIMELINE' as const, label: 'Timeline', icon: Clock },
    { id: 'EVIDENCE' as const, label: 'Evidence', icon: FolderGit2, count: investigation.evidence.length },
    { id: 'HYPOTHESES' as const, label: 'Hypotheses', icon: Layers, count: investigation.hypotheses.length },
    { id: 'ROOT_CAUSE' as const, label: 'Root Cause', icon: Sparkles },
    { id: 'RESOLUTION' as const, label: 'Resolution', icon: Wrench },
    { id: 'AGENT_TASK' as const, label: 'Agent Task', icon: Cpu },
    { id: 'VERIFICATION' as const, label: 'Sandbox Verification', icon: FileCheck, badge: 'GATE' },
  ];

  return (
    <div className="flex flex-col h-full overflow-hidden bg-[#030712] text-slate-100 tech-grid-bg font-sans antialiased">
      {/* Top Header: Incident Identity & Context */}
      <div className="hud-corner p-6 border-b border-cyan-500/25 bg-[#080e1a]/90 backdrop-blur-xl transition-colors shrink-0 space-y-4 shadow-[0_4px_25px_rgba(0,0,0,0.5)]">
        <div className="flex flex-col lg:flex-row justify-between lg:items-center gap-4">
          <div>
            <div className="flex items-center gap-2 mb-2 flex-wrap">
              <CanonicalIdBadge id={investigation.id} />
              <SeverityBadge severity={investigation.severity} />
              <StageBadge stage={investigation.stage} />
              {investigation.jiraKey && <JiraBadge ticket={investigation.jiraKey} />}
              {investigation.pullRequest && <PRBadge pr={investigation.pullRequest} />}
              {investigation.blastRadius && <BlastRadiusBadge text={investigation.blastRadius} />}
            </div>

            <div className="flex items-baseline gap-3">
              <h1 className="text-2xl font-extrabold text-white font-heading tracking-tight drop-shadow-[0_0_15px_rgba(255,255,255,0.15)]">
                {investigation.title}
              </h1>
            </div>

            <div className="flex items-center gap-4 text-xs text-slate-500 dark:text-slate-400 mt-1 font-mono flex-wrap">
              <span>Service: <strong className="text-slate-700 dark:text-slate-300">{investigation.service}</strong></span>
              <span>&bull;</span>
              <span>Env: <strong className="text-slate-700 dark:text-slate-300">{investigation.environment}</strong></span>
              <span>&bull;</span>
              <span>Commit: <strong className="text-indigo-600 dark:text-indigo-400">{investigation.context.commit}</strong></span>
              <span>&bull;</span>
              <span>Repo: <strong className="text-slate-700 dark:text-slate-300">{investigation.context.repository}</strong></span>
            </div>

            {/* REAL REPOSITORY INVENTORY PILLS */}
            {((investigation as any).repositoryInventory || (investigation as any).telemetry?.repositoryInventory) && (
              <div className="flex items-center gap-1.5 mt-2 flex-wrap text-[11px] font-mono">
                <span className="text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded bg-indigo-500/10 text-indigo-300 dark:bg-indigo-950/60 dark:text-indigo-300 border border-indigo-500/30">
                  REAL REPO GROUNDED
                </span>
                {(((investigation as any).repositoryInventory || (investigation as any).telemetry?.repositoryInventory)?.languages || []).map((l: string) => (
                  <span key={l} className="px-2 py-0.5 rounded bg-slate-800/60 text-slate-700 dark:text-slate-300 border border-white/10 dark:border-slate-700">
                    {l}
                  </span>
                ))}
                {(((investigation as any).repositoryInventory || (investigation as any).telemetry?.repositoryInventory)?.frameworks || []).map((f: string) => (
                  <span key={f} className="px-2 py-0.5 rounded bg-emerald-500/100/10/40 text-emerald-300 border border-emerald-500/30 font-semibold">
                    {f}
                  </span>
                ))}
                <span className="px-2 py-0.5 rounded bg-slate-800/60 text-slate-500 dark:text-slate-400">
                  {(((investigation as any).repositoryInventory || (investigation as any).telemetry?.repositoryInventory)?.total_files || 0)} files indexed
                </span>
              </div>
            )}
          </div>

          <div className="flex items-center gap-3 shrink-0">
            <ConfidenceMeter confidence={investigation.confidence} />
            <div className="h-9 w-px bg-slate-200 dark:border-slate-800" />
            <button
              onClick={() => setActiveSection('VERIFICATION')}
              className="gradient-border-btn flex items-center gap-2 px-4 py-2.5 rounded-lg text-white font-heading font-bold text-xs shadow-lg hover:scale-[1.02] transition-all cursor-pointer"
            >
              <FileCheck size={14} />
              <span>Sandbox Gate</span>
            </button>
          </div>
        </div>

        {/* TYPED STATE MACHINE DISPLAY (Section 5 & 24) */}
        <div className="pt-2 border-t border-white/10">
          <div className="flex items-center gap-1 sm:gap-2 overflow-x-auto py-1 text-xs">
            {STATE_STAGES.map((s, idx) => {
              const isPassed = currentStageIndex > s.minIndex;
              const isCurrent = currentStageIndex === s.minIndex;
              
              const stageToTab: Record<string, WorkspaceSection> = {
                'EVIDENCE': 'EVIDENCE',
                'PLANNING': 'OVERVIEW',
                'INVESTIGATION': 'TIMELINE',
                'ROOT_CAUSE': 'ROOT_CAUSE',
                'RESOLUTION': 'RESOLUTION',
                'SANDBOX': 'VERIFICATION',
                'DEPLOYMENT': 'VERIFICATION'
              };

              return (
                <div key={s.key} className="flex items-center gap-1 sm:gap-2 shrink-0">
                  <button
                    onClick={() => {
                      audioFx.click();
                      if (stageToTab[s.key]) setActiveSection(stageToTab[s.key]);
                    }}
                    className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-heading font-semibold transition-all hover:scale-[1.03] cursor-pointer ${
                      isPassed
                        ? 'bg-emerald-950/50 text-emerald-300 border border-emerald-500/50 shadow-[0_0_12px_rgba(16,185,129,0.2)]'
                        : isCurrent
                        ? 'bg-gradient-to-r from-sky-500 to-indigo-600 text-white font-bold shadow-[0_0_18px_rgba(56,189,248,0.4)] border border-sky-300/40'
                        : 'bg-slate-900/60 text-slate-400 border border-white/5 hover:border-white/20'
                    }`}
                  >
                    {isPassed ? (
                      <Check size={13} className="text-emerald-400 shrink-0" />
                    ) : isCurrent ? (
                      <span className="w-2 h-2 rounded-full bg-white animate-ping shrink-0" />
                    ) : (
                      <span className="w-2 h-2 rounded-full border border-slate-500 shrink-0" />
                    )}
                    <span>{s.label}</span>
                  </button>
                  {idx < STATE_STAGES.length - 1 && (
                    <span className="text-slate-600 text-xs font-mono">&rarr;</span>
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {/* EPISTEMIC GATING ALERT BANNER */}
        {(investigation.stage === 'INSUFFICIENT_EVIDENCE' || investigation.rootCause?.status === 'INSUFFICIENT_EVIDENCE') && (
          <div className="mt-3 p-3 rounded-lg bg-amber-500/100/10 border border-amber-400/40 dark:border-amber-500/30 flex items-center justify-between gap-3 text-xs">
            <div className="flex items-center gap-2 text-amber-900 dark:text-amber-200 font-mono">
              <AlertTriangle size={15} className="text-amber-600 dark:text-amber-400 shrink-0" />
              <span>
                <strong>ORACLE Epistemic Gate:</strong> Insufficient empirical evidence to isolate a deterministic root cause without guessing. Downstream code modification is gated until missing telemetry is collected.
              </span>
            </div>
            <button
              onClick={() => setActiveSection('ROOT_CAUSE')}
              className="px-2.5 py-1 rounded bg-amber-600 text-white font-bold text-[10px] shrink-0 hover:bg-amber-500/100 transition-colors"
            >
              Inspect Gap Analysis &rarr;
            </button>
          </div>
        )}
      </div>

      {/* Primary Section Switcher Tabs (Section 5) */}
      <div className="border-b border-white/10 bg-[#080d1a]/95 backdrop-blur-xl px-6 shrink-0 overflow-x-auto">
        <div className="flex items-center gap-2">
          {WORKSPACE_SECTIONS.map((sec) => {
            const Icon = sec.icon;
            const isActive = activeSection === sec.id;
            return (
              <button
                key={sec.id}
                onClick={() => {
                  audioFx.click();
                  setActiveSection(sec.id);
                }}
                className={`flex items-center gap-2 py-2.5 px-4 rounded-lg text-xs font-heading font-semibold tracking-tight transition-all shrink-0 ${
                  isActive
                    ? 'bg-gradient-to-r from-sky-500/20 to-indigo-500/20 text-sky-200 border border-sky-400/50 shadow-[0_0_15px_rgba(56,189,248,0.25)] font-bold'
                    : 'text-slate-400 hover:text-white hover:bg-white/5 border border-transparent'
                }`}
              >
                <Icon size={14} />
                <span>{sec.label}</span>
                {sec.count !== undefined && (
                  <span className={`text-[10px] px-1.5 py-0.2 rounded font-mono ${
                    isActive
                      ? 'bg-indigo-100 text-indigo-300 dark:bg-indigo-900 dark:text-indigo-200'
                      : 'bg-slate-100 text-slate-500 dark:bg-slate-800 dark:text-slate-400'
                  }`}>
                    {sec.count}
                  </span>
                )}
                {sec.badge && (
                  <span className="text-[9px] px-1.5 py-0.2 rounded bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300 font-mono font-bold">
                    {sec.badge}
                  </span>
                )}
              </button>
            );
          })}
        </div>
      </div>

      {/* Main Content Area */}
      <div className="flex-1 overflow-y-auto p-6 lg:p-8">
        
        {/* ========================================================================= */}
        {/* SECTION 1: OVERVIEW */}
        {/* ========================================================================= */}
        {activeSection === 'OVERVIEW' && (
          <div className="space-y-6 max-w-5xl mx-auto">
            {/* EXECUTIVE INCIDENT GUIDE & ARCHITECTURE BRIEF */}
            <motion.div 
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              className="glass-panel-elevated p-6 rounded-2xl border border-sky-500/30 bg-gradient-to-br from-slate-900/90 via-slate-900/70 to-indigo-950/40 relative overflow-hidden"
            >
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-white/10">
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 rounded-lg bg-sky-500/20 border border-sky-500/30 flex items-center justify-center text-sky-400">
                    <Sparkles size={18} />
                  </div>
                  <div>
                    <h2 className="text-lg font-bold text-white font-heading tracking-tight">
                      End-to-End Incident Resolution Guide
                    </h2>
                    <p className="text-xs text-slate-400">
                      Understand how ORACLE detected, isolated, and synthesized a verified fix for {investigation.id}.
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => {
                      audioFx.click();
                      setActiveSection('VERIFICATION');
                    }}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 border border-emerald-500/30 font-semibold text-xs transition-colors"
                  >
                    <ShieldCheck size={14} />
                    <span>Run Verification Replay</span>
                  </button>
                  <button
                    onClick={() => {
                      audioFx.click();
                      setActiveSection('RESOLUTION');
                    }}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-sky-500 hover:bg-sky-400 text-slate-950 font-bold text-xs transition-colors"
                  >
                    <FileCode2 size={14} />
                    <span>Inspect Code Diff</span>
                  </button>
                </div>
              </div>

              {/* 4-Step Summary Grid */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 mt-4">
                <div className="p-3.5 rounded-xl bg-slate-950/60 border border-white/5 space-y-1">
                  <span className="text-[10px] font-mono font-bold text-rose-400 uppercase tracking-wider block">
                    1. Observed Symptom
                  </span>
                  <h3 className="text-xs font-bold text-white font-heading truncate">
                    HTTP 500 Outage
                  </h3>
                  <p className="text-[11px] text-slate-300 leading-snug">
                    {investigation.context.stackTraceRaw ? 'Unhandled NullPointer in webhook handler.' : 'Error spike detected in production service.'}
                  </p>
                </div>

                <div className="p-3.5 rounded-xl bg-slate-950/60 border border-white/5 space-y-1">
                  <span className="text-[10px] font-mono font-bold text-sky-400 uppercase tracking-wider block">
                    2. Forensic Evidence
                  </span>
                  <h3 className="text-xs font-bold text-white font-heading truncate">
                    {investigation.evidence.length} Correlated Items
                  </h3>
                  <p className="text-[11px] text-slate-300 leading-snug">
                    Culprit commit <span className="font-mono text-cyan-300">{investigation.context.commit || '8f2a41d'}</span> identified via git log & telemetry.
                  </p>
                </div>

                <div className="p-3.5 rounded-xl bg-slate-950/60 border border-white/5 space-y-1">
                  <span className="text-[10px] font-mono font-bold text-indigo-400 uppercase tracking-wider block">
                    3. Ranked Root Cause
                  </span>
                  <h3 className="text-xs font-bold text-white font-heading truncate">
                    {investigation.hypotheses[0]?.title || 'Null Idempotency Key'}
                  </h3>
                  <p className="text-[11px] text-slate-300 leading-snug">
                    {investigation.confidence}% AI confidence score with deterministic code path proof.
                  </p>
                </div>

                <div className="p-3.5 rounded-xl bg-slate-950/60 border border-white/5 space-y-1">
                  <span className="text-[10px] font-mono font-bold text-emerald-400 uppercase tracking-wider block">
                    4. Zero-Trust Sandbox
                  </span>
                  <h3 className="text-xs font-bold text-white font-heading truncate">
                    Verified Clean (18.42s)
                  </h3>
                  <p className="text-[11px] text-slate-300 leading-snug">
                    Simulated production traffic replayed in Docker sandbox with 0 regressions.
                  </p>
                </div>
              </div>
            </motion.div>
            {/* Architecture Dependency Topology Graph */}
            {investigation.topology && (
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 flex items-center gap-1.5">
                    <Network size={14} />
                    Production Architecture Topology & Fault Isolation
                  </span>
                  <span className="text-[11px] font-mono text-slate-400">Upstream Caller &rarr; Target &rarr; Dependency</span>
                </div>
                <TopologyGraph 
                  nodes={investigation.topology.nodes} 
                  edges={investigation.topology.edges} 
                />
              </div>
            )}

            {/* Quick Summary Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="p-5 rounded-xl border border-white/10 bg-slate-900/80 shadow-2xs space-y-3">
                <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-slate-600 dark:text-slate-400">
                  <Terminal size={14} className="text-indigo-500" />
                  <span>Observed Fault Signature</span>
                </div>
                <pre className="p-3 rounded-lg bg-slate-950 text-emerald-300 font-mono text-xs overflow-x-auto leading-relaxed border border-slate-800 max-h-48">
                  {investigation.context.stackTraceRaw}
                </pre>
              </div>

              <div className="p-5 rounded-xl border border-white/10 bg-slate-900/80 shadow-2xs space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold uppercase tracking-wider text-slate-600 dark:text-slate-400 flex items-center gap-1.5">
                    <Sparkles size={14} className="text-amber-500" />
                    Isolated Root Cause
                  </span>
                  <span className="text-xs font-mono font-bold text-indigo-600 dark:text-indigo-400">
                    {investigation.confidence}% Confidence
                  </span>
                </div>
                <div className="text-sm font-bold text-white">
                  {investigation.rootCause?.title || 'Redis cache-key namespace mismatch'}
                </div>
                <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                  {investigation.rootCause?.explanationChain?.[0] || 'Commit 8f31a2 altered the cache prefix without backward-compatible dual lookup. Active customer sessions cannot be retrieved from Redis, triggering NoneType errors during payment authorization.'}
                </p>
                <div className="pt-2 flex items-center gap-3">
                  <button
                    onClick={() => setActiveSection('ROOT_CAUSE')}
                    className="text-xs font-semibold text-indigo-600 dark:text-indigo-400 hover:underline flex items-center gap-1"
                  >
                    <span>Inspect Reasoning Chain</span>
                    <ArrowRight size={12} />
                  </button>
                  <button
                    onClick={() => setActiveSection('VERIFICATION')}
                    className="text-xs font-semibold text-emerald-600 dark:text-emerald-400 hover:underline flex items-center gap-1"
                  >
                    <span>View Sandbox Proof</span>
                    <ArrowRight size={12} />
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* SECTION 2: TIMELINE */}
        {/* ========================================================================= */}
        {activeSection === 'TIMELINE' && (
          <div className="max-w-4xl mx-auto space-y-4">
            <div className="flex items-center justify-between pb-2 border-b border-white/10">
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-700 dark:text-slate-300">
                Investigation & Verification Sequence
              </h3>
              <span className="text-[11px] font-mono text-slate-400">Audit-Grade Trace</span>
            </div>

            <div className="space-y-3">
              {investigation.timeline.map((evt, idx) => (
                <div 
                  key={evt.id || idx}
                  className="glass-card p-5 border border-white/10 hover:border-sky-400/50 bg-[#0c1324]/80 rounded-xl shadow-lg flex items-start gap-4 transition-all hover:scale-[1.008]"
                >
                  <div className="px-2.5 py-1 rounded-md bg-sky-950/60 border border-sky-500/40 text-sky-300 font-mono text-xs font-bold shrink-0 shadow-[0_0_12px_rgba(56,189,248,0.2)]">
                    {evt.timestamp}
                  </div>
                  <div className="flex-1 space-y-1.5">
                    <div className="flex items-center justify-between gap-2">
                      <h4 className="text-sm font-bold font-heading text-white flex items-center gap-2">
                        <span className="w-1.5 h-1.5 rounded-full bg-sky-400 animate-pulse" />
                        {evt.action}
                      </h4>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-slate-800/80 text-sky-300 border border-sky-500/30 font-bold uppercase tracking-wider">
                        {evt.stage}
                      </span>
                    </div>
                    <p className="text-xs text-slate-300 font-sans leading-relaxed">
                      {evt.details}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* SECTION 3: EVIDENCE EXPLORER (Section 6) */}
        {/* ========================================================================= */}
        {activeSection === 'EVIDENCE' && (
          <div className="max-w-6xl mx-auto space-y-4">
            <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-3 pb-2 border-b border-white/10">
              <div>
                <h3 className="text-xs font-bold uppercase tracking-wider text-white flex items-center gap-2">
                  <FolderGit2 size={16} className="text-indigo-600" />
                  <span>Evidence Explorer — First-Class Provenance Vault</span>
                </h3>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                  Multi-modal evidence corroborating root causes with explicit hypothesis associations and provenance tracking.
                </p>
              </div>

              {/* Category Filter */}
              <div className="flex items-center gap-1.5 overflow-x-auto text-xs font-mono">
                {['ALL', 'CODE', 'AST', 'GIT', 'TEST', 'LOG', 'CONFIG', 'METRIC', 'REPOSITORY'].map((cat) => (
                  <button
                    key={cat}
                    onClick={() => setEvidenceFilter(cat)}
                    className={`px-2.5 py-1 rounded-md border transition-all ${
                      evidenceFilter === cat
                        ? 'bg-indigo-600 text-white border-indigo-600 font-bold'
                        : 'bg-slate-900/80 text-slate-600 dark:text-slate-400 border-white/10 hover:bg-slate-800/70'
                    }`}
                  >
                    {cat}
                  </button>
                ))}
              </div>
            </div>

            {/* Evidence List & Inspector split view */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
              {/* Evidence List */}
              <div className="lg:col-span-5 space-y-2 max-h-[600px] overflow-y-auto pr-1">
                {filteredEvidence.map((item) => (
                  <div
                    key={item.id}
                    onClick={() => setSelectedEvidence(item)}
                    className={`p-3.5 rounded-xl border cursor-pointer transition-all text-xs space-y-2 ${
                      selectedEvidence?.id === item.id
                        ? 'bg-indigo-500/10/90 dark:bg-indigo-950/40 border-indigo-400 dark:border-indigo-700 shadow-xs'
                        : 'bg-slate-900/80 border-white/10 hover:border-white/15'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-mono font-bold text-white">
                        {item.id}
                      </span>
                      <EvidenceCategoryBadge category={item.category} />
                    </div>

                    <div className="font-semibold text-slate-800 dark:text-slate-200">
                      {item.source} {item.location && <span className="font-mono text-indigo-600 dark:text-indigo-400">({item.location})</span>}
                    </div>

                    <p className="text-[11px] text-slate-500 dark:text-slate-400 line-clamp-2">
                      {item.summary}
                    </p>

                    {/* Visually obvious provenance tag */}
                    <div className="pt-1 flex items-center justify-between text-[10px] text-slate-400 font-mono">
                      <span className="truncate max-w-[200px]" title={item.provenance}>
                        &bull; {item.provenance}
                      </span>
                      {item.supportsHypotheses.length > 0 && (
                        <span className="px-1.5 py-0.2 rounded bg-emerald-100 dark:bg-emerald-950 text-emerald-300 font-bold">
                          Supports {item.supportsHypotheses.join(', ')}
                        </span>
                      )}
                    </div>
                  </div>
                ))}
              </div>

              {/* Evidence Inspector Detail */}
              <div className="lg:col-span-7 p-5 rounded-xl border border-white/10 bg-slate-900/80 shadow-2xs space-y-4">
                {selectedEvidence ? (
                  <>
                    <div className="flex items-center justify-between pb-3 border-b border-white/10">
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-mono font-extrabold text-sm text-white">
                            {selectedEvidence.id}
                          </span>
                          <span className="text-xs px-2 py-0.5 rounded bg-slate-800/60 font-mono text-slate-600 dark:text-slate-400">
                            {selectedEvidence.type}
                          </span>
                        </div>
                        <div className="text-xs font-semibold text-slate-700 dark:text-slate-300 mt-1">
                          Source: {selectedEvidence.source} {selectedEvidence.location && `(${selectedEvidence.location})`}
                        </div>
                      </div>

                      <span className={`px-2.5 py-1 rounded text-xs font-bold font-mono border ${
                        selectedEvidence.relevance === 'CRITICAL'
                          ? 'bg-rose-50 text-rose-700 border-rose-200 dark:bg-rose-950 dark:text-rose-300'
                          : 'bg-indigo-500/10 text-indigo-300 border-indigo-500/30 dark:bg-indigo-950 dark:text-indigo-300'
                      }`}>
                        {selectedEvidence.relevance}
                      </span>
                    </div>

                    {/* Visually Obvious Provenance Banner (Section 6) */}
                    <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/60 border border-white/10 dark:border-slate-700 text-xs font-mono space-y-1">
                      <span className="text-slate-400 block text-[10px] uppercase font-bold tracking-wider">
                        Cryptographic & Lineage Provenance:
                      </span>
                      <span className="text-indigo-600 dark:text-indigo-300 font-bold break-all">
                        {selectedEvidence.provenance}
                      </span>
                    </div>

                    {/* Content Preview */}
                    <div className="space-y-1.5">
                      <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400 block">
                        Raw Evidence Content
                      </span>
                      <pre className="p-4 rounded-xl bg-slate-950 text-slate-200 font-mono text-xs overflow-x-auto leading-relaxed border border-slate-800 max-h-72 shadow-inner">
                        {selectedEvidence.content}
                      </pre>
                    </div>

                    {/* Hypothesis Mapping */}
                    <div className="pt-2 grid grid-cols-2 gap-3 text-xs">
                      <div className="p-3 rounded-lg bg-emerald-500/10/60 dark:bg-emerald-950/30 border border-emerald-500/30/60">
                        <span className="text-[10px] font-bold text-emerald-800 dark:text-emerald-300 uppercase block mb-1">
                          Supports Hypotheses:
                        </span>
                        <span className="font-mono font-bold text-emerald-900 dark:text-emerald-200">
                          {selectedEvidence.supportsHypotheses.length > 0 ? selectedEvidence.supportsHypotheses.join(', ') : 'None'}
                        </span>
                      </div>

                      <div className="p-3 rounded-lg bg-rose-50/60 dark:bg-rose-950/30 border border-rose-500/30/60">
                        <span className="text-[10px] font-bold text-rose-800 dark:text-rose-300 uppercase block mb-1">
                          Contradicts Hypotheses:
                        </span>
                        <span className="font-mono font-bold text-rose-900 dark:text-rose-200">
                          {selectedEvidence.contradictsHypotheses.length > 0 ? selectedEvidence.contradictsHypotheses.join(', ') : 'None'}
                        </span>
                      </div>
                    </div>
                  </>
                ) : (
                  <div className="p-8 text-center text-xs text-slate-400">
                    Select an evidence item from the list to inspect its contents and provenance.
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* SECTION 4: HYPOTHESES (Section 7) */}
        {/* ========================================================================= */}
        {activeSection === 'HYPOTHESES' && (
          <div className="max-w-4xl mx-auto space-y-6">
            <div className="pb-2 border-b border-white/10">
              <h3 className="text-xs font-bold uppercase tracking-wider text-white flex items-center gap-2">
                <Layers size={16} className="text-indigo-600" />
                <span>Hypothesis Investigation & Elimination</span>
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                Competing hypotheses evaluated against telemetry. Contradicting evidence is never hidden.
              </p>
            </div>

            <div className="space-y-4">
              {investigation.hypotheses.map((h) => {
                const isStrong = h.status === 'STRONGLY_SUPPORTED' || h.status === 'CONFIRMED';
                return (
                  <div
                    key={h.id}
                    className={`p-5 rounded-xl border transition-all space-y-3 shadow-2xs ${
                      isStrong
                        ? 'bg-emerald-500/10/40 dark:bg-emerald-950/20 border-emerald-300 dark:border-emerald-800/80'
                        : 'bg-slate-900/80 border-white/10'
                    }`}
                  >
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <div className="flex items-center gap-3">
                        <span className="font-mono font-extrabold text-sm text-white">
                          {h.id}
                        </span>
                        <h4 className="text-sm font-bold text-white">
                          {h.title}
                        </h4>
                      </div>

                      <span className={`px-3 py-1 rounded text-xs font-bold font-mono border self-start sm:self-auto ${
                        isStrong
                          ? 'bg-emerald-100 text-emerald-800 border-emerald-300 dark:bg-emerald-950 dark:text-emerald-300 dark:border-emerald-700'
                          : 'bg-rose-100 text-rose-800 border-rose-300 dark:bg-rose-950 dark:text-rose-300 dark:border-rose-700'
                      }`}>
                        {h.status.replace(/_/g, ' ')}
                      </span>
                    </div>

                    <p className="text-xs text-slate-600 dark:text-slate-300">
                      {h.description}
                    </p>

                    {/* Supporting vs Contradicting Counts (Section 7) */}
                    <div className="grid grid-cols-2 gap-3 pt-2 text-xs">
                      <div className="p-3 rounded-lg bg-emerald-500/100/10/40 border border-emerald-500/30/60 flex items-center justify-between">
                        <span className="font-semibold text-emerald-800 dark:text-emerald-300">
                          Supporting Evidence:
                        </span>
                        <span className="font-mono font-bold text-emerald-900 dark:text-emerald-200">
                          {h.supportingCount ?? h.supportingEvidenceIds.length} items ({h.supportingEvidenceIds.join(', ') || 'None'})
                        </span>
                      </div>

                      <div className="p-3 rounded-lg bg-rose-500/10/40 border border-rose-500/30/60 flex items-center justify-between">
                        <span className="font-semibold text-rose-800 dark:text-rose-300">
                          Contradicting Evidence:
                        </span>
                        <span className="font-mono font-bold text-rose-900 dark:text-rose-200">
                          {h.contradictingCount ?? h.contradictingEvidenceIds.length} items ({h.contradictingEvidenceIds.join(', ') || '0'})
                        </span>
                      </div>
                    </div>

                    {/* Evaluator Rationale */}
                    <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/60 text-xs text-slate-600 dark:text-slate-300 font-mono">
                      <strong>Evaluator Note:</strong> {h.rationale}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* SECTION 5: ROOT CAUSE (Section 8 & 20) */}
        {/* ========================================================================= */}
        {activeSection === 'ROOT_CAUSE' && (
          <div className="max-w-4xl mx-auto space-y-6">
            {investigation.stage === 'INSUFFICIENT_EVIDENCE' || investigation.rootCause?.status === 'INSUFFICIENT_EVIDENCE' ? (
              <div className="p-6 rounded-xl border border-amber-300 dark:border-amber-800 bg-gradient-to-br from-amber-50/70 via-white to-slate-50 dark:from-amber-950/40 dark:via-slate-900 dark:to-slate-900 shadow-xs space-y-5">
                <div className="flex items-center justify-between pb-3 border-b border-amber-500/30 dark:border-amber-900/60">
                  <div className="flex items-center gap-2.5">
                    <div className="p-2 rounded-lg bg-amber-600 text-white shadow-xs">
                      <AlertTriangle size={18} />
                    </div>
                    <div>
                      <span className="text-[10px] font-bold uppercase tracking-wider text-amber-300 block">
                        ORACLE Epistemic Determination
                      </span>
                      <h2 className="text-base font-extrabold text-white">
                        ROOT CAUSE: Insufficient Evidence
                      </h2>
                    </div>
                  </div>

                  <div className="text-right">
                    <span className="text-xl font-black text-amber-600 dark:text-amber-400 font-mono">
                      {investigation.confidence}%
                    </span>
                    <span className="block text-[10px] font-bold text-amber-600 dark:text-amber-400">
                      INSUFFICIENT EVIDENCE
                    </span>
                  </div>
                </div>

                {/* Why Section (Section 20) */}
                <div className="space-y-2">
                  <span className="text-xs font-bold uppercase tracking-wider text-slate-700 dark:text-slate-300 block">
                    Why:
                  </span>
                  <div className="p-3.5 rounded-lg bg-slate-800/80 border border-amber-500/30/60 text-xs text-slate-700 dark:text-slate-300 space-y-1.5 leading-relaxed">
                    {(investigation.rootCause?.explanationChain || [
                      'The stack trace identifies the failure location, but multiple upstream causes remain possible.',
                      'Deployment diff and configuration telemetry are absent.',
                    ]).map((line, i) => (
                      <div key={i} className="flex items-start gap-2">
                        <span className="font-mono font-bold text-amber-600 dark:text-amber-400">&bull;</span>
                        <span>{line}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Missing Evidence & Recommended Next Actions */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
                  <div className="p-3.5 rounded-lg bg-slate-800/80 border border-white/10 dark:border-slate-700 space-y-2">
                    <span className="text-[11px] font-bold text-rose-300 uppercase block">
                      Missing Evidence:
                    </span>
                    <div className="space-y-1.5 font-mono text-[11px] text-slate-600 dark:text-slate-300">
                      {(investigation.rootCause?.missingEvidence || [
                        'Deployment history and commit diff',
                        'Relevant runtime configuration',
                        'Minimal reproduction test case',
                      ]).map((item, i) => (
                        <div key={i} className="flex items-center gap-1.5">
                          <XCircle size={12} className="text-rose-500 shrink-0" />
                          <span>{item}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="p-3.5 rounded-lg bg-slate-800/80 border border-white/10 dark:border-slate-700 space-y-2">
                    <span className="text-[11px] font-bold text-indigo-300 uppercase block">
                      Recommended Next Actions:
                    </span>
                    <div className="space-y-1.5 text-[11px] text-slate-600 dark:text-slate-300 font-mono">
                      {(investigation.rootCause?.recommendedNextActions || [
                        '1. Inspect recent deployment history and commits.',
                        '2. Retrieve active runtime configuration parameters.',
                        '3. Generate minimal reproducer test.',
                      ]).map((action, i) => (
                        <div key={i} className="flex items-start gap-1.5">
                          <ArrowRight size={12} className="text-indigo-500 shrink-0 mt-0.5" />
                          <span>{action}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Epistemic note */}
                <div className="p-3 rounded-lg bg-amber-100/60 dark:bg-amber-950/40 border border-amber-300 dark:border-amber-800 text-[11px] text-amber-900 dark:text-amber-200 flex items-center gap-2">
                  <Info size={14} className="shrink-0 text-amber-600" />
                  <span>
                    <strong>ORACLE Epistemic Contract:</strong> Never manufacture a root cause. A high confidence score must NEVER override missing or contradictory evidence. This is a successful ORACLE outcome — not a failure.
                  </span>
                </div>
              </div>
            ) : (
              <div className="p-6 rounded-xl border border-indigo-300 dark:border-indigo-800 bg-gradient-to-br from-indigo-50/60 via-white to-slate-50 dark:from-indigo-950/40 dark:via-slate-900 dark:to-slate-900 shadow-xs space-y-4">
                <div className="flex items-center justify-between pb-3 border-b border-indigo-500/30 dark:border-indigo-900/60">
                  <div className="flex items-center gap-2.5">
                    <div className="p-2 rounded-lg bg-indigo-600 text-white shadow-xs">
                      <Sparkles size={18} />
                    </div>
                    <div>
                      <span className="text-[10px] font-bold uppercase tracking-wider text-indigo-300 block">
                        Isolated Root Cause
                      </span>
                      <h2 className="text-base font-extrabold text-white">
                        {investigation.rootCause?.title || 'Redis cache-key namespace mismatch'}
                      </h2>
                    </div>
                  </div>

                  <div className="text-right">
                    <span className="text-xl font-black text-indigo-600 dark:text-indigo-400 font-mono">
                      {investigation.confidence}%
                    </span>
                    <span className="block text-[10px] font-bold text-emerald-600 dark:text-emerald-400">
                      STRONGLY SUPPORTED
                    </span>
                  </div>
                </div>

                {/* Supporting & Contradicting Lists */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
                  <div className="p-3.5 rounded-lg bg-slate-800/80 border border-white/10 dark:border-slate-700 space-y-1.5">
                    <span className="text-[11px] font-bold text-emerald-300 uppercase block">
                      Supporting Evidence ({investigation.rootCause?.supportingEvidenceIds.length || 3})
                    </span>
                    <div className="space-y-1 font-mono text-[11px] text-slate-600 dark:text-slate-300">
                      {investigation.rootCause?.supportingEvidenceIds.map((id) => (
                        <div key={id} className="flex items-center gap-1.5">
                          <Check size={12} className="text-emerald-500" />
                          <span>{id} (Verified in evidence vault)</span>
                        </div>
                      )) || (
                        <>
                          <div>&bull; E-018 (Source Code: payment_service.py:184)</div>
                          <div>&bull; E-024 (Logs: NIL response on customer:v2:*)</div>
                          <div>&bull; E-031 (Git Diff: commit 8f31a2 prefix change)</div>
                        </>
                      )}
                    </div>
                  </div>

                  <div className="p-3.5 rounded-lg bg-slate-800/80 border border-white/10 dark:border-slate-700 space-y-1.5">
                    <span className="text-[11px] font-bold text-slate-500 dark:text-slate-400 uppercase block">
                      Contradicting Evidence (0)
                    </span>
                    <p className="text-xs text-slate-500 dark:text-slate-400">
                      Explicitly evaluated database connection exhaustion and network partitions. Zero contradictions observed across telemetry channels.
                    </p>
                  </div>
                </div>

                {/* Investigation Reasoning Chain (Section 8) */}
                <div className="space-y-2 pt-2 border-t border-white/10">
                  <span className="text-xs font-bold uppercase tracking-wider text-slate-700 dark:text-slate-300 flex items-center gap-1.5">
                    <GitBranch size={14} className="text-indigo-500" />
                    Investigation Reasoning Chain
                  </span>
                  <div className="space-y-1.5 pl-2 border-l-2 border-indigo-400 dark:border-indigo-600 ml-1 text-xs text-slate-700 dark:text-slate-300">
                    {(investigation.rootCause?.explanationChain || [
                      'Production error: payment_service.py:184 raised AttributeError',
                      'payment_service.py:184: get_customer() returns None unexpectedly',
                      'Redis lookup misses: key customer:v2:<id> returned NIL',
                      'Git diff changed key namespace: commit 8f31a2 altered prefix from user:cust: to customer:v2:',
                      'Reproduction confirms failure: existing active sessions exist only under legacy key namespace',
                    ]).map((step, i) => (
                      <div key={i} className="flex items-start gap-2">
                        <span className="font-mono font-bold text-indigo-600 dark:text-indigo-400">{i + 1}.</span>
                        <span>{step}</span>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="pt-2 flex justify-end">
                  <button
                    onClick={() => setActiveSection('RESOLUTION')}
                    className="flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-900 dark:bg-white text-white dark:text-slate-900 font-bold text-xs shadow-xs hover:bg-slate-800 transition-all"
                  >
                    <span>Proceed to Resolution Planning</span>
                    <ArrowRight size={13} />
                  </button>
                </div>
              </div>
            )}
          </div>
        )}

        {/* ========================================================================= */}
        {/* SECTION 6: RESOLUTION PLANNING (Section 9) */}
        {/* ========================================================================= */}
        {activeSection === 'RESOLUTION' && (
          <div className="max-w-4xl mx-auto space-y-6">
            <div className="p-6 rounded-xl border border-white/10 bg-slate-900/80 shadow-2xs space-y-5">
              <div className="flex items-center justify-between pb-3 border-b border-white/10">
                <div className="flex items-center gap-2.5">
                  <div className="p-2 rounded-lg bg-emerald-600 text-white shadow-xs">
                    <Wrench size={18} />
                  </div>
                  <div>
                    <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block">
                      Resolution Strategy
                    </span>
                    <h3 className="text-sm font-extrabold text-white">
                      {investigation.resolution?.recommendation || 'Implement backward-compatible Redis key lookup.'}
                    </h3>
                  </div>
                </div>

                <span className="px-2.5 py-1 rounded text-xs font-bold font-mono bg-amber-500/10 text-amber-700 border border-amber-500/30 dark:bg-amber-950 dark:text-amber-300 dark:border-amber-800">
                  Risk: {investigation.resolution?.risk || 'MEDIUM'}
                </span>
              </div>

              {/* Affected Files */}
              <div className="space-y-1.5">
                <span className="text-xs font-bold uppercase tracking-wider text-slate-600 dark:text-slate-400 block">
                  Affected Target Files
                </span>
                <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/60 border border-white/10 dark:border-slate-700 font-mono text-xs text-slate-800 dark:text-slate-200 space-y-1">
                  {(investigation.resolution?.affectedFiles || [
                    'src/customer/repository.py',
                    'src/payment/payment_service.py',
                  ]).map((file) => (
                    <div key={file} className="flex items-center gap-2">
                      <FileCode2 size={13} className="text-indigo-500" />
                      <span>{file}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Required Implementation Steps */}
              <div className="space-y-1.5">
                <span className="text-xs font-bold uppercase tracking-wider text-slate-600 dark:text-slate-400 block">
                  Required Changes (4 Steps)
                </span>
                <div className="p-4 rounded-xl border border-white/10 bg-slate-900/80 text-xs space-y-2">
                  {(investigation.resolution?.steps || [
                    '1. Support legacy namespace: Check customer:v2:<id> first; if None, fallback to user:cust:<id>.',
                    '2. Preserve new namespace: On cache miss fallback, write-through populate customer:v2:<id>.',
                    '3. Add regression test: Validate dual-lookup and miss behavior in tests/test_customer_cache_fallback.py.',
                    '4. Validate cache miss behavior: Ensure graceful fallback when neither key exists in cache.',
                  ]).map((step, i) => (
                    <div key={i} className="flex items-start gap-2.5">
                      <span className="w-5 h-5 rounded-full bg-indigo-500/100/10 text-indigo-300 flex items-center justify-center font-mono font-bold text-[10px] shrink-0 mt-0.5">
                        {i + 1}
                      </span>
                      <span className="text-slate-700 dark:text-slate-300 leading-relaxed">{step}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Primary Action Button (Section 9) */}
              <div className="pt-2 flex justify-end">
                <button
                  onClick={() => setActiveSection('AGENT_TASK')}
                  className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-indigo-600 hover:bg-indigo-500/100 text-white font-bold text-xs shadow-xs transition-all"
                >
                  <Cpu size={15} />
                  <span>Generate Coding-Agent Task</span>
                </button>
              </div>
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* SECTION 7: AGENT TASK GENERATOR (Section 10) */}
        {/* ========================================================================= */}
        {activeSection === 'AGENT_TASK' && (
          <div className="max-w-4xl mx-auto space-y-5">
            <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-3 pb-2 border-b border-white/10">
              <div>
                <h3 className="text-xs font-bold uppercase tracking-wider text-white flex items-center gap-2">
                  <Cpu size={16} className="text-indigo-600" />
                  <span>Coding-Agent Task Generator</span>
                </h3>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                  Formats verified root cause, evidence, and constraints for Claude Code, Codex, or generic coding agents.
                </p>
              </div>

              {/* Format Switcher */}
              <div className="flex items-center gap-1 bg-slate-200/70 dark:bg-slate-800 p-1 rounded-lg text-xs font-medium">
                {(['Claude Code', 'Claude CLI', 'Codex', 'Generic Coding Agent'] as AgentTargetFormat[]).map((fmt) => (
                  <button
                    key={fmt}
                    onClick={() => setAgentFormat(fmt)}
                    className={`px-3 py-1 rounded-md transition-all ${
                      agentFormat === fmt
                        ? 'bg-slate-900/80 text-white shadow-xs font-bold'
                        : 'text-slate-600 dark:text-slate-400 hover:text-slate-900'
                    }`}
                  >
                    {fmt}
                  </button>
                ))}
              </div>
            </div>

            {/* Generated Task Card */}
            <div className="p-5 rounded-xl border border-white/10 bg-slate-900/80 shadow-2xs space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono font-bold text-indigo-600 dark:text-indigo-400">
                  Target: {agentFormat} &bull; INC-1042 Structured Task
                </span>

                <div className="flex items-center gap-2">
                  <button
                    onClick={copyTaskPrompt}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-slate-800/60 hover:bg-slate-200 text-slate-700 dark:text-slate-300 font-semibold text-xs transition-colors"
                  >
                    {copiedTask ? <Check size={13} className="text-emerald-600" /> : <Copy size={13} />}
                    <span>{copiedTask ? 'Copied' : 'Copy Prompt'}</span>
                  </button>
                  <button
                    onClick={downloadTaskPrompt}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-slate-800/60 hover:bg-slate-200 text-slate-700 dark:text-slate-300 font-semibold text-xs transition-colors"
                  >
                    <Download size={13} />
                    <span>Download Task</span>
                  </button>
                </div>
              </div>

              <pre className="p-4 rounded-xl bg-slate-950 text-slate-200 font-mono text-xs overflow-x-auto leading-relaxed border border-slate-800 max-h-96 shadow-inner whitespace-pre-wrap">
                {agentTaskPrompt}
              </pre>

              <div className="p-3 rounded-lg bg-amber-500/100/10/40 border border-amber-500/30/40 text-[11px] text-amber-900 dark:text-amber-200 flex items-center gap-2">
                <Info size={14} className="shrink-0 text-amber-600" />
                <span>Zero-Trust Contract: Any patch produced by an agent will be strictly gated by the 5-stage Sandbox Replay before deployment clearance.</span>
              </div>

              <div className="pt-2 flex justify-end">
                <button
                  onClick={() => setActiveSection('VERIFICATION')}
                  className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-500/100 text-white font-bold text-xs shadow-xs transition-all"
                >
                  <span>Step 4: Run Sandbox Verification</span>
                  <ArrowRight size={13} />
                </button>
              </div>
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* SECTION 8: SANDBOX VERIFICATION & PROOF ENGINE (Sections 11 - 22) */}
        {/* ========================================================================= */}
        {activeSection === 'VERIFICATION' && (
          <div className="space-y-6 max-w-5xl mx-auto">
            {/* Header with Mode Toggle */}
            <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-3 pb-2 border-b border-white/10">
              <div>
                <h2 className="text-sm font-bold text-white flex items-center gap-2">
                  <ShieldCheck size={18} className="text-emerald-600 dark:text-emerald-400" />
                  <span>Sandbox Verification & Empirical Proof Engine</span>
                </h2>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                  Zero-trust empirical gate: Replays real traffic to prove the original failure is resolved and 0 regressions exist.
                </p>
              </div>

              {/* Simulation outcome toggle (Section 21) */}
              <div className="flex items-center gap-2 text-xs font-mono">
                <span className="text-slate-400 text-[11px]">GATE TEST MODE:</span>
                <button
                  onClick={() => setVerificationSimState('PASS')}
                  className={`px-2.5 py-1 rounded-md border transition-colors ${
                    verificationSimState === 'PASS'
                      ? 'bg-emerald-500/10 text-emerald-700 border-emerald-300 dark:bg-emerald-950/40 dark:text-emerald-300 dark:border-emerald-800/60 font-bold shadow-xs'
                      : 'bg-slate-100 text-slate-600 border-white/10 dark:bg-slate-800 dark:text-slate-400 dark:border-slate-700'
                  }`}
                >
                  Pass Outcome
                </button>
                <button
                  onClick={() => setVerificationSimState('FAIL')}
                  className={`px-2.5 py-1 rounded-md border transition-colors ${
                    verificationSimState === 'FAIL'
                      ? 'bg-rose-50 text-rose-700 border-rose-300 dark:bg-rose-950/40 dark:text-rose-300 dark:border-rose-800/60 font-bold shadow-xs'
                      : 'bg-slate-100 text-slate-600 border-white/10 dark:bg-slate-800 dark:text-slate-400 dark:border-slate-700'
                  }`}
                >
                  Fail Outcome
                </button>
              </div>
            </div>

            {/* EDUCATIONAL / CONCEPTUAL EXPLAINER CARD */}
            <div className="rounded-xl border border-blue-200 dark:border-blue-900/50 bg-gradient-to-br from-blue-50/70 via-indigo-50/30 to-white dark:from-blue-950/30 dark:via-slate-900 dark:to-slate-900 p-5 shadow-2xs space-y-4">
              <div className="flex items-start gap-3">
                <div className="p-2 rounded-lg bg-blue-600 text-white shrink-0 mt-0.5 shadow-xs">
                  <Cpu size={18} />
                </div>
                <div className="space-y-1">
                  <h3 className="text-xs font-bold text-blue-950 dark:text-blue-200 uppercase tracking-wider flex items-center gap-2">
                    <span>What is Sandbox Verification & How Does ORACLE Prove It?</span>
                    <span className="text-[10px] normal-case font-normal px-2 py-0.5 rounded-full bg-blue-100 dark:bg-blue-900/60 text-blue-700 dark:text-blue-300">
                      Zero-Trust Autonomous Validation
                    </span>
                  </h3>
                  <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                    AI models and automated suggestions cannot be trusted on faith. <strong>Sandbox Verification</strong> is ORACLE's empirical proof pipeline. Before any code is deployed or merged, ORACLE boots an ephemeral micro-container isolated from production, applies the patch, and executes rigorous test suites to establish mathematical and empirical certainty.
                  </p>
                </div>
              </div>

              {/* The 4 Pillars of Proof Grid (Section 15) */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 pt-1">
                <div className="p-3 rounded-lg border border-white/10 bg-white/80 dark:bg-slate-900/80 space-y-1.5 shadow-2xs">
                  <div className="flex items-center gap-2 text-indigo-600 dark:text-indigo-400">
                    <Shield size={14} className="shrink-0" />
                    <span className="text-[11px] font-bold">1. Negative Proof</span>
                  </div>
                  <p className="text-[11px] text-slate-500 dark:text-slate-400 leading-normal">
                    Replays the exact failing condition. Proves that the crash or error <strong>no longer occurs</strong>.
                  </p>
                </div>

                <div className="p-3 rounded-lg border border-white/10 bg-white/80 dark:bg-slate-900/80 space-y-1.5 shadow-2xs">
                  <div className="flex items-center gap-2 text-emerald-600 dark:text-emerald-400">
                    <CheckCircle2 size={14} className="shrink-0" />
                    <span className="text-[11px] font-bold">2. Zero Regressions</span>
                  </div>
                  <p className="text-[11px] text-slate-500 dark:text-slate-400 leading-normal">
                    Executes the full existing test suite (<strong>843 unit & integration tests</strong>) to prove zero side effects.
                  </p>
                </div>

                <div className="p-3 rounded-lg border border-white/10 bg-white/80 dark:bg-slate-900/80 space-y-1.5 shadow-2xs">
                  <div className="flex items-center gap-2 text-amber-600 dark:text-amber-400">
                    <Code2 size={14} className="shrink-0" />
                    <span className="text-[11px] font-bold">3. Scope Containment</span>
                  </div>
                  <p className="text-[11px] text-slate-500 dark:text-slate-400 leading-normal">
                    Abstract Syntax Tree (AST) analysis verifies that only authorized files and methods were modified.
                  </p>
                </div>

                <div className="p-3 rounded-lg border border-white/10 bg-white/80 dark:bg-slate-900/80 space-y-1.5 shadow-2xs">
                  <div className="flex items-center gap-2 text-purple-600 dark:text-purple-400">
                    <Lock size={14} className="shrink-0" />
                    <span className="text-[11px] font-bold">4. Signed Attestation</span>
                  </div>
                  <p className="text-[11px] text-slate-500 dark:text-slate-400 leading-normal">
                    Binds the patch SHA-256 and test exit codes into a <strong>cryptographically signed seal</strong> before unlock.
                  </p>
                </div>
              </div>
            </div>

            {/* Live Interactive Verification Action Card (Section 12 & 13) */}
            <div className="p-5 rounded-xl border border-indigo-500/30 dark:border-indigo-900/60 bg-slate-900/80 shadow-2xs space-y-4">
              <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-bold text-white uppercase tracking-wider">
                      Interactive Sandbox Execution Runner
                    </span>
                    <span className="text-[10px] px-2 py-0.5 rounded-md bg-indigo-100 dark:bg-indigo-950 text-indigo-300 font-mono">
                      Target: {investigation.id}
                    </span>
                  </div>
                  <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                    Triggers the 5-stage pipeline via <code className="font-mono text-indigo-600 dark:text-indigo-400">POST /api/v1/investigations/{investigation.id}/verify</code>.
                  </p>
                </div>

                <button
                  disabled={isRunningVerification}
                  onClick={handleExecuteVerification}
                  className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-indigo-600 hover:bg-indigo-500/100 disabled:bg-indigo-400 text-white text-xs font-bold transition-all shadow-sm shrink-0"
                >
                  {isRunningVerification ? (
                    <>
                      <RefreshCw size={14} className="animate-spin" />
                      <span>Running Sandbox Replay...</span>
                    </>
                  ) : (
                    <>
                      <Play size={14} />
                      <span>Run Sandbox Replay Now</span>
                    </>
                  )}
                </button>
              </div>

              {/* Step-by-Step 5-Stage Replay Stepper (Section 12) */}
              <div className="pt-2 border-t border-white/10">
                <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-2">
                  Sandbox Pipeline Progress
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
                  {[
                    { step: 1, label: '1. Container Boot', sub: 'Isolated Micro-VM' },
                    { step: 2, label: '2. Apply Git Patch', sub: 'AST Scope Check' },
                    { step: 3, label: '3. Replay Failure', sub: 'Negative Assertion' },
                    { step: 4, label: '4. Regression Suite', sub: '843 Tests Passed' },
                    { step: 5, label: '5. Attestation Sealed', sub: 'SHA-256 Token' },
                  ].map((s) => {
                    const isDone = replayPhase >= s.step || (!isRunningVerification && investigation.verification?.status === 'VERIFIED');
                    const isActive = isRunningVerification && replayPhase === s.step;
                    return (
                      <div
                        key={s.step}
                        className={`p-2.5 rounded-lg border text-xs transition-all ${
                          isDone
                            ? 'bg-emerald-500/10/80 border-emerald-300 dark:bg-emerald-950/30 dark:border-emerald-800/60 text-emerald-900 dark:text-emerald-200'
                            : isActive
                            ? 'bg-indigo-500/10 border-indigo-400 dark:bg-indigo-950/40 dark:border-indigo-700 text-indigo-900 dark:text-indigo-200 ring-2 ring-indigo-500/20'
                            : 'bg-slate-50 border-white/10 dark:bg-slate-800/40 dark:border-slate-800 text-slate-400 dark:text-slate-500'
                        }`}
                      >
                        <div className="flex items-center gap-1.5 font-semibold">
                          {isDone ? (
                            <Check size={12} className="text-emerald-600 dark:text-emerald-400" />
                          ) : isActive ? (
                            <RefreshCw size={12} className="animate-spin text-indigo-600 dark:text-indigo-400" />
                          ) : (
                            <span className="w-3 h-3 rounded-full border border-white/15 dark:border-slate-600 inline-block" />
                          )}
                          <span className="truncate">{s.label}</span>
                        </div>
                        <div className="text-[10px] text-slate-500 dark:text-slate-400 mt-0.5 truncate">
                          {s.sub}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>

            {verificationSuccessToast && (
              <div className="p-3.5 rounded-lg bg-emerald-500/100/10/50 border border-emerald-300 dark:border-emerald-800 text-xs text-emerald-800 dark:text-emerald-300 flex items-center justify-between animate-fade-in shadow-xs">
                <div className="flex items-center gap-2">
                  <CheckCircle2 size={16} className="text-emerald-600 shrink-0" />
                  <span>Sandbox replay executed successfully! Verification artifacts generated and attested.</span>
                </div>
                <span className="text-[10px] font-mono text-emerald-600">FastAPI 200 OK</span>
              </div>
            )}

            {/* DEPLOYMENT GATE STATUS CARD (Section 20 & 21) */}
            {verificationSimState === 'PASS' ? (
              <div className="p-5 rounded-xl border border-emerald-300 dark:border-emerald-800/80 bg-emerald-500/10/80 dark:bg-emerald-950/30 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 shadow-xs">
                <div className="flex items-start gap-3">
                  <div className="p-2.5 rounded-xl bg-emerald-600 text-white shrink-0 shadow-xs">
                    <CheckCircle2 size={24} />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono font-bold uppercase text-emerald-800 dark:text-emerald-300">
                        DEPLOYMENT GATE: ✓ CLEARED
                      </span>
                      <span className="text-[10px] px-2 py-0.2 rounded bg-emerald-100 dark:bg-emerald-900 text-emerald-200 font-bold">
                        ORACLE VERDICT: FIX VERIFIED
                      </span>
                    </div>
                    <p className="text-xs text-slate-600 dark:text-slate-300 mt-1">
                      Negative Proof (✓), Zero Regressions (843 passed ✓), Scope Containment (2/2 files ✓), Cryptographic Proof (✓).
                    </p>
                    <p className="text-[11px] text-slate-400 mt-0.5">
                      *Note: Gate clearance authorizes rollout; actual deployment remains a separate authorized action.
                    </p>
                  </div>
                </div>
                <span className="text-xs font-bold px-3.5 py-1.5 rounded-lg bg-emerald-600 text-white shrink-0 shadow-xs font-mono">
                  GATE_CLEARED
                </span>
              </div>
            ) : (
              <div className="p-5 rounded-xl border border-rose-300 dark:border-rose-900/80 bg-rose-50/80 dark:bg-rose-950/30 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 shadow-xs">
                <div className="flex items-start gap-3">
                  <div className="p-2.5 rounded-xl bg-rose-600 text-white shrink-0 shadow-xs">
                    <AlertTriangle size={24} />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono font-bold uppercase text-rose-800 dark:text-rose-300">
                        DEPLOYMENT GATE: 🔒 BLOCKED
                      </span>
                      <span className="text-[10px] px-2 py-0.2 rounded bg-rose-100 dark:bg-rose-900 text-rose-800 dark:text-rose-200 font-bold">
                        VERIFICATION FAILED
                      </span>
                    </div>
                    <p className="text-xs text-slate-600 dark:text-slate-300 mt-1">
                      Regression suite detected 1 failure (LockAcquisitionDeadlockException). Automated deployment gate locked to prevent outage.
                    </p>
                    <p className="text-[11px] text-slate-400 mt-0.5">
                      Recommended Action: Revise lock acquisition hierarchy in mutex_manager.py before re-attempting sandbox verification.
                    </p>
                  </div>
                </div>
                <span className="text-xs font-bold px-3.5 py-1.5 rounded-lg bg-rose-600 text-white shrink-0 shadow-xs font-mono">
                  DEPLOYMENT_BLOCKED
                </span>
              </div>
            )}

            {/* THE 4 ARTIFACT INSPECTOR SUBTABS (Section 16 - 19) */}
            <div className="rounded-xl border border-white/10 bg-slate-900/80 shadow-2xs overflow-hidden">
              <div className="px-4 py-3 border-b border-white/10 flex flex-col sm:flex-row sm:items-center justify-between gap-2 bg-slate-50/50 dark:bg-slate-800/30">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-bold text-white uppercase tracking-wider">
                    Empirical Proof Artifacts
                  </span>
                  <span className="text-[10px] px-2 py-0.5 rounded bg-slate-200 dark:bg-slate-800 text-slate-600 dark:text-slate-400 font-mono">
                    4 Inspectors
                  </span>
                </div>

                {/* Subtab Switcher */}
                <div className="flex items-center gap-1 bg-slate-200/70 dark:bg-slate-800 p-1 rounded-lg text-xs font-medium">
                  <button
                    onClick={() => setSandboxArtifactTab('OUTPUT')}
                    className={`flex items-center gap-1.5 px-3 py-1 rounded-md transition-all ${
                      sandboxArtifactTab === 'OUTPUT'
                        ? 'bg-slate-900/80 text-white shadow-xs font-bold'
                        : 'text-slate-600 dark:text-slate-400 hover:text-slate-900'
                    }`}
                  >
                    <Terminal size={12} />
                    <span>Terminal Output</span>
                  </button>

                  <button
                    onClick={() => setSandboxArtifactTab('TEST_CODE')}
                    className={`flex items-center gap-1.5 px-3 py-1 rounded-md transition-all ${
                      sandboxArtifactTab === 'TEST_CODE'
                        ? 'bg-slate-900/80 text-white shadow-xs font-bold'
                        : 'text-slate-600 dark:text-slate-400 hover:text-slate-900'
                    }`}
                  >
                    <Code2 size={12} />
                    <span>Reproducer Test</span>
                  </button>

                  <button
                    onClick={() => setSandboxArtifactTab('DIFF')}
                    className={`flex items-center gap-1.5 px-3 py-1 rounded-md transition-all ${
                      sandboxArtifactTab === 'DIFF'
                        ? 'bg-slate-900/80 text-white shadow-xs font-bold'
                        : 'text-slate-600 dark:text-slate-400 hover:text-slate-900'
                    }`}
                  >
                    <GitBranch size={12} />
                    <span>Unified Git Patch</span>
                  </button>

                  <button
                    onClick={() => setSandboxArtifactTab('CERTIFICATE')}
                    className={`flex items-center gap-1.5 px-3 py-1 rounded-md transition-all ${
                      sandboxArtifactTab === 'CERTIFICATE'
                        ? 'bg-slate-900/80 text-white shadow-xs font-bold'
                        : 'text-slate-600 dark:text-slate-400 hover:text-slate-900'
                    }`}
                  >
                    <Award size={12} />
                    <span>Signed Certificate</span>
                  </button>
                </div>
              </div>

              {/* Subtab 1: Terminal Output (Section 16) */}
              {sandboxArtifactTab === 'OUTPUT' && (
                <div className="p-4 space-y-3">
                  <div className="flex items-center justify-between text-xs text-slate-500 font-mono">
                    <span className="flex items-center gap-1.5">
                      <Terminal size={13} className="text-emerald-500" />
                      <span>Command: {investigation.verification?.testCommand || 'pytest tests/test_payment_remediation.py -v'}</span>
                    </span>
                    <div className="flex items-center gap-2">
                      <button
                        onClick={downloadTerminalLogs}
                        className="flex items-center gap-1 px-2 py-1 rounded bg-slate-800/60 text-[11px] hover:bg-slate-200"
                      >
                        <Download size={11} />
                        <span>Download Log</span>
                      </button>
                      <span className="text-[11px] text-slate-400">Exit Code: {verificationSimState === 'PASS' ? '0 (OK)' : '1 (FAIL)'}</span>
                    </div>
                  </div>
                  <pre className="p-4 rounded-xl bg-slate-950 text-slate-200 font-mono text-xs overflow-x-auto leading-relaxed border border-slate-800 max-h-80 shadow-inner">
                    {verificationSimState === 'PASS' 
                      ? (investigation.verification?.terminalOutput || `$ pytest tests/test_payment_remediation.py tests/regression/ -v

============================= test session starts ==============================
platform linux -- Python 3.11.9, pytest-8.1.1
rootdir: /app/payment-api
collected 843 items

tests/test_payment_remediation.py::test_payment_failure_regression_legacy_fallback PASSED [  0%]
tests/regression/test_suite.py::test_regression_suite_pass [842 tests]            PASSED [100%]

============================== 843 passed in 18.42s ============================
Exit code: 0

VERIFICATION RESULT: ALL CHECKS PASSED
CRYPTOGRAPHIC SEAL: ATTEST-SHA256-10429a8f4c2e`)
                      : `$ pytest tests/test_payment_remediation.py tests/regression/ -v

============================= test session starts ==============================
platform linux -- Python 3.11.9, pytest-8.1.1
collected 843 items

tests/test_payment_remediation.py::test_payment_failure_regression_legacy_fallback PASSED [  0%]
tests/regression/test_mutex.py::test_concurrent_checkout_lock FAILED              [ 98%]

=================================== FAILURES ===================================
_________________________ test_concurrent_checkout_lock ________________________
Deadlock detected during concurrent lock acquisition in mutex_manager.py:42
=========================== 1 failed, 842 passed in 14.12s =====================
Exit code: 1`}
                  </pre>
                </div>
              )}

              {/* Subtab 2: Reproducer Test Code (Section 17) */}
              {sandboxArtifactTab === 'TEST_CODE' && (
                <div className="p-4 space-y-3">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-mono text-slate-600 dark:text-slate-300 font-semibold flex items-center gap-1.5">
                      <Code2 size={13} className="text-indigo-500" />
                      <span>Negative Assertion Test File: tests/test_payment_remediation.py</span>
                    </span>
                    <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300 font-bold">
                      TEST STATUS: ✓ PASSED (Negative Proof)
                    </span>
                  </div>
                  <pre className="p-4 rounded-xl bg-slate-950 text-emerald-300 font-mono text-xs overflow-x-auto leading-relaxed border border-slate-800 max-h-80 shadow-inner">
                    {investigation.verification?.testScript || `# tests/test_payment_remediation.py
import pytest
from unittest.mock import MagicMock
from src.customer.repository import CustomerRepository

def test_payment_failure_regression_legacy_fallback():
    """Validates that customer lookup falls back to legacy namespace when new namespace misses."""
    mock_redis = MagicMock()
    mock_redis.get.side_effect = lambda k: b'{"id": "cust_99214", "is_active_subscriber": true}' if "user:cust:" in k else None
    
    repo = CustomerRepository(cache=mock_redis)
    customer = repo.get_customer("cust_99214")
    
    assert customer is not None, "Failed to retrieve customer under legacy namespace"
    assert customer.is_active_subscriber is True
    # Ensure write-through migrated the record
    mock_redis.set.assert_called_with("customer:v2:cust_99214", customer.to_json())`}
                  </pre>
                </div>
              )}

              {/* Subtab 3: Unified Git Patch (Section 18) */}
              {sandboxArtifactTab === 'DIFF' && (
                <div className="p-4 space-y-3">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-mono text-slate-600 dark:text-slate-300 font-semibold flex items-center gap-1.5">
                      <GitBranch size={13} className="text-purple-500" />
                      <span>Unified Git Diff Applied to Ephemeral Container</span>
                    </span>
                    <span className="text-[11px] font-mono text-slate-400">
                      Files Changed: 2 &bull; Insertions: 8 &bull; Deletions: 3
                    </span>
                  </div>
                  <pre className="p-4 rounded-xl bg-slate-950 text-slate-200 font-mono text-xs overflow-x-auto leading-relaxed border border-slate-800 max-h-80 shadow-inner">
                    {investigation.verification?.gitPatch || `--- a/src/customer/repository.py
+++ b/src/customer/repository.py
@@ -90,4 +90,9 @@ class CustomerRepository:
     def get_customer(self, customer_id: str) -> Optional[Customer]:
-        key = f"customer:v2:{customer_id}"
-        return self.cache.get(key)
+        new_key = f"customer:v2:{customer_id}"
+        customer = self.cache.get(new_key)
+        if customer is None:
+            old_key = f"user:cust:{customer_id}"
+            customer = self.cache.get(old_key)
+            if customer is not None:
+                self.cache.set(new_key, customer)
+        return customer`}
                  </pre>
                </div>
              )}

              {/* Subtab 4: Cryptographic Attestation Certificate (Section 19) */}
              {sandboxArtifactTab === 'CERTIFICATE' && (
                <div className="p-6 space-y-5">
                  <div className="border border-emerald-300 dark:border-emerald-800/80 rounded-xl bg-gradient-to-br from-emerald-50/50 via-white to-slate-50 dark:from-emerald-950/20 dark:via-slate-900 dark:to-slate-900 p-6 shadow-xs space-y-4">
                    <div className="flex items-center justify-between pb-4 border-b border-emerald-500/30/60">
                      <div className="flex items-center gap-3">
                        <div className="p-2.5 rounded-xl bg-emerald-600 text-white shadow-xs">
                          <Award size={24} />
                        </div>
                        <div>
                          <div className="text-xs font-bold uppercase tracking-wider text-emerald-800 dark:text-emerald-300">
                            Cryptographic Proof of Remediation
                          </div>
                          <div className="text-sm font-extrabold text-white">
                            ORACLE Verification Authority Certificate
                          </div>
                        </div>
                      </div>
                      <div className="text-right font-mono text-xs">
                        <span className={`px-2.5 py-1 rounded-md font-bold ${
                          verificationSimState === 'PASS' 
                            ? 'bg-emerald-100 dark:bg-emerald-900/60 text-emerald-800 dark:text-emerald-300' 
                            : 'bg-rose-100 dark:bg-rose-900/60 text-rose-800 dark:text-rose-300'
                        }`}>
                          {verificationSimState === 'PASS' ? 'STATUS: VERIFIED (CLEARED)' : 'STATUS: BLOCKED'}
                        </span>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs font-mono">
                      <div>
                        <span className="text-slate-400 block text-[11px]">ATTESTATION TOKEN:</span>
                        <span className="font-bold text-white break-all">
                          {investigation.verification?.attestation?.token || 'ATTEST-SHA256-10429a8f4c2e710b89d4'}
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-400 block text-[11px]">PATCH SHA-256 DIGEST:</span>
                        <span className="text-slate-700 dark:text-slate-300 break-all">
                          {investigation.verification?.attestation?.digest || '7d8a9b2c3e4f5061728394a5b6c7d8e9f0123456789abcdef0123456789abcde'}
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-400 block text-[11px]">CONTAINER ID:</span>
                        <span className="text-slate-700 dark:text-slate-300">
                          {investigation.verification?.attestation?.containerId || 'sandbox-orc-inc-1042-microvm-04'}
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-400 block text-[11px]">AUTHORITY SIGNER:</span>
                        <span className="text-slate-700 dark:text-slate-300">
                          {investigation.verification?.attestation?.signer || 'ORACLE Verification Authority (Ed25519)'}
                        </span>
                      </div>
                    </div>

                    <div className="p-3 rounded-lg bg-emerald-100/50 dark:bg-emerald-950/40 border border-emerald-500/30/40 text-[11px] text-emerald-900 dark:text-emerald-200 flex items-center gap-2">
                      <Lock size={14} className="shrink-0 text-emerald-600 dark:text-emerald-400" />
                      <span>Tamper-proof seal: This token binds the exact AST diff and container test exit codes. Any subsequent code tampering invalidates this attestation.</span>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* 5-Point Quality Gate Checklist */}
            <div className="border border-white/10 bg-slate-900/80 rounded-xl divide-y divide-slate-100 dark:divide-slate-800/60 shadow-2xs">
              <div className="p-4 bg-slate-50/50 dark:bg-slate-800/30 text-xs font-bold uppercase tracking-wider text-slate-600 dark:text-slate-300">
                5-Point Quality Gate Criteria
              </div>
              {[
                { 
                  label: '1. Original Error Path Eliminated', 
                  pass: verificationSimState === 'PASS', 
                  note: verificationSimState === 'PASS' ? 'Replayed 500 requests against target service: 0 errors returned.' : 'Failed on request #14: Connection timeout raised.'
                },
                { 
                  label: '2. Incident Reproducer Test Suite', 
                  pass: verificationSimState === 'PASS', 
                  note: 'tests/test_payment_remediation.py executed with all assertions passing.' 
                },
                { 
                  label: '3. Existing Test Suite Unbroken', 
                  pass: verificationSimState === 'PASS', 
                  note: 'All 843 existing service unit and integration tests executed without regressions.' 
                },
                { 
                  label: '4. Static Analysis & Type Contracts', 
                  pass: true, 
                  note: 'Ruff and Mypy reported 0 type errors or schema contract violations.' 
                },
                { 
                  label: '5. AST Scope Containment Check', 
                  pass: true, 
                  note: 'AST diff confirms 2/2 files modified; 0 modifications outside permitted files boundary.' 
                },
              ].map((chk, i) => (
                <div key={i} className="p-4 flex items-center justify-between text-xs">
                  <div>
                    <div className="font-semibold text-white flex items-center gap-2">
                      <span>{chk.label}</span>
                    </div>
                    <div className="text-slate-500 dark:text-slate-400 mt-0.5">{chk.note}</div>
                  </div>
                  <span className={`text-[11px] font-medium px-2.5 py-0.5 rounded border shrink-0 ${
                    chk.pass
                      ? 'bg-emerald-500/10 text-emerald-700 border-emerald-500/30 dark:bg-emerald-950/40 dark:text-emerald-300 dark:border-emerald-800/60'
                      : 'bg-rose-50 text-rose-700 border-rose-200 dark:bg-rose-950/40 dark:text-rose-300 dark:border-rose-900/60'
                  }`}>
                    {chk.pass ? 'Passed' : 'Failed'}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

      </div>
    </div>
  );
}
