import React, { useState } from 'react';
import { IncidentInvestigation, AgentTargetFormat } from '../../types/oracle';
import { Copy, Check, Terminal, FileCode2, ShieldAlert, Cpu, ArrowRight, Download, Info } from 'lucide-react';

interface ResolutionViewProps {
  investigation: IncidentInvestigation;
  onOpenVerification: () => void;
}

export function ResolutionView({ investigation, onOpenVerification }: ResolutionViewProps) {
  const [copied, setCopied] = useState(false);
  const [selectedFormat, setSelectedFormat] = useState<AgentTargetFormat>('Claude Code');

  const resolution = investigation.resolution;

  const promptContent = `You are resolving software engineering incident ${investigation.id}.

INCIDENT:
${investigation.title}
Target Service: ${investigation.service} | Environment: ${investigation.environment} | Severity: ${investigation.severity}

ROOT CAUSE:
${investigation.rootCause ? investigation.rootCause.title : 'Redis cache-key namespace mismatch'} (Confidence: ${investigation.confidence}%)
Reasoning Chain:
${investigation.rootCause?.explanationChain.map((e, idx) => `  ${idx + 1}. ${e}`).join('\n') || '  1. Replayed production error trace'}

AFFECTED FILES:
${resolution?.affectedFiles.map((f) => `- ${f}`).join('\n') || '- src/customer/repository.py\n- src/payment/payment_service.py'}

REQUIRED CHANGES:
${resolution?.steps.map((s, i) => `${i + 1}. ${s}`).join('\n') || '1. Support legacy namespace.\n2. Preserve new namespace.\n3. Add regression test.\n4. Validate cache miss behavior.'}

TEST REQUIREMENTS:
1. Run reproducer test: original failure condition must no longer reproduce.
2. Run full regression suite (842 tests): all existing tests must pass with exit code 0.
3. Validate cache miss behavior.

CONSTRAINTS:
- Do NOT modify unrelated functionality.
- Ensure backwards-compatible lookup for existing cache records.
- If your investigation contradicts the supplied root cause, STOP and report the discrepancy instead of blindly applying the proposed fix.

VERIFICATION:
The original failure must no longer reproduce.
Run the existing regression suite.
Report all changed files and test results for ORACLE Sandbox Verification.`;

  const handleCopy = () => {
    navigator.clipboard.writeText(promptContent);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const blob = new Blob([promptContent], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `ORACLE-TASK-${investigation.id}.txt`;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="p-6 lg:p-8 max-w-5xl mx-auto space-y-6 text-slate-200 dark:text-slate-200">
      <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-3 pb-4 border-b border-white/10">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold tracking-tight text-white font-heading font-bold flex items-center gap-2">
              <Cpu size={22} className="text-indigo-600 dark:text-indigo-400" />
              <span>Resolutions & Coding-Agent Tasks</span>
            </h1>
            <span className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-slate-800/60 text-slate-300 dark:text-slate-300 border border-white/10 dark:border-slate-700">
              Target: {investigation.id}
            </span>
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
            Engineered remediation plan with precise constraints and verification targets for coding agents.
          </p>
        </div>

        <button
          onClick={onOpenVerification}
          className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500/100 text-white text-xs font-bold transition-colors shadow-xs self-start sm:self-auto"
        >
          <span>Open Sandbox Verification</span>
          <ArrowRight size={13} />
        </button>
      </div>

      {/* Target Format Switcher */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-1 bg-slate-200/70 dark:bg-slate-800 p-1 rounded-lg text-xs font-medium">
          {(['Claude Code', 'Claude CLI', 'Codex', 'Generic Coding Agent'] as AgentTargetFormat[]).map((fmt) => (
            <button
              key={fmt}
              onClick={() => setSelectedFormat(fmt)}
              className={`px-3 py-1 rounded-md transition-all ${
                selectedFormat === fmt
                  ? 'bg-slate-900/80 text-white font-heading font-bold shadow-xs font-bold'
                  : 'text-slate-600 dark:text-slate-400 hover:text-white'
              }`}
            >
              {fmt}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleCopy}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-slate-800/60 hover:bg-slate-200 text-slate-300 dark:text-slate-300 font-semibold text-xs transition-colors"
          >
            {copied ? <Check size={13} className="text-emerald-600" /> : <Copy size={13} />}
            <span>{copied ? 'Copied' : 'Copy Prompt'}</span>
          </button>
          <button
            onClick={handleDownload}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-slate-800/60 hover:bg-slate-200 text-slate-300 dark:text-slate-300 font-semibold text-xs transition-colors"
          >
            <Download size={13} />
            <span>Download Task</span>
          </button>
        </div>
      </div>

      {/* Task Prompt Display */}
      <div className="border border-white/10 bg-slate-900/80 rounded-xl p-5 shadow-2xs space-y-4">
        <div className="flex items-center justify-between">
          <span className="text-xs font-bold uppercase tracking-wider text-slate-600 dark:text-slate-400">
            Generated Implementation Task ({selectedFormat})
          </span>
          <span className="text-[11px] font-mono text-slate-400">
            Bounded Context &bull; Zero-Trust
          </span>
        </div>

        <pre className="p-4 rounded-xl bg-slate-950 text-slate-200 font-mono text-xs overflow-x-auto leading-relaxed border border-slate-800 max-h-[420px] shadow-inner whitespace-pre-wrap">
          {promptContent}
        </pre>

        <div className="p-3 rounded-lg bg-indigo-500/10/70 dark:bg-indigo-950/40 border border-indigo-500/30/40 text-[11px] text-indigo-900 dark:text-indigo-200 flex items-center gap-2">
          <Info size={14} className="shrink-0 text-indigo-600 dark:text-indigo-400" />
          <span>Evidence vs Assumptions: This prompt is composed strictly from corroborated logs, git diffs, and AST frames. It explicitly directs the agent to halt if code examination contradicts the root cause.</span>
        </div>
      </div>
    </div>
  );
}
