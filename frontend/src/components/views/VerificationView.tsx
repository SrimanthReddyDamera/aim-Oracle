import React, { useState } from 'react';
import { IncidentInvestigation } from '../../types/oracle';
import { 
  CheckCircle2, 
  AlertTriangle, 
  RefreshCw, 
  Check, 
  Terminal, 
  Code2, 
  GitBranch, 
  Award, 
  ShieldCheck, 
  Cpu, 
  Shield, 
  Lock, 
  Play, 
  Download,
  Info 
} from 'lucide-react';

interface VerificationViewProps {
  investigation: IncidentInvestigation;
  onRunVerification?: (outcome: 'VERIFIED' | 'FAILED') => Promise<void> | void;
}

export function VerificationView({ investigation, onRunVerification }: VerificationViewProps) {
  const [outcome, setOutcome] = useState<'VERIFIED' | 'FAILED'>(
    investigation.verification?.status === 'FAILED' ? 'FAILED' : 'VERIFIED'
  );
  const [isRunning, setIsRunning] = useState(false);
  const [replayPhase, setReplayPhase] = useState<number>(0);
  const [activeArtifactTab, setActiveArtifactTab] = useState<'OUTPUT' | 'TEST_CODE' | 'DIFF' | 'SCOPE' | 'CERTIFICATE'>('OUTPUT');

  const handleRunSuite = async () => {
    setIsRunning(true);
    setReplayPhase(1);
    setTimeout(() => setReplayPhase(2), 350);
    setTimeout(() => setReplayPhase(3), 750);
    setTimeout(() => setReplayPhase(4), 1200);
    try {
      if (onRunVerification) {
        await onRunVerification(outcome);
      }
      setTimeout(() => setReplayPhase(5), 1600);
    } finally {
      setTimeout(() => setIsRunning(false), 1900);
    }
  };

  const downloadTerminalLogs = () => {
    const text = investigation.verification?.terminalOutput || 'Pytest logs';
    const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `ORACLE-VERIFY-${investigation.id}.log`;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="p-6 lg:p-8 max-w-5xl mx-auto space-y-6 text-slate-200 dark:text-slate-200">
      {/* Header with Mode Toggle */}
      <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-3 pb-4 border-b border-white/10">
        <div>
          <div className="flex items-center gap-2 flex-wrap">
            <h1 className="text-xl font-bold tracking-tight text-white font-heading font-bold flex items-center gap-2">
              <ShieldCheck size={22} className="text-emerald-600 dark:text-emerald-400" />
              <span>Sandbox Verification & Empirical Proof Engine</span>
            </h1>
            <span className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-slate-800/60 text-slate-300 dark:text-slate-300 border border-white/10 dark:border-slate-700">
              Target: {investigation.id}
            </span>
            {investigation.verification?.isRealSandbox ? (
              <span className="text-[11px] font-mono px-2.5 py-0.5 rounded-full bg-emerald-500/100/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30 flex items-center gap-1.5 font-bold">
                <ShieldCheck size={12} />
                REAL ISOLATED SANDBOX
              </span>
            ) : (
              <span className="text-[11px] font-mono px-2.5 py-0.5 rounded-full bg-amber-500/100/10 text-amber-600 dark:text-amber-400 border border-amber-500/30 flex items-center gap-1.5 font-bold">
                <Info size={12} />
                DEMO / MOCK
              </span>
            )}
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
            Zero-trust isolation gate: Replays real traffic and test suites to mathematically prove 0 regressions.
          </p>
        </div>

        <div className="flex items-center gap-3 self-start sm:self-auto">
          {/* Outcome toggle for evaluation */}
          <div className="flex items-center gap-1.5 p-1 rounded-lg border border-white/10 dark:border-slate-700 bg-slate-800/60 text-xs">
            <span className="text-slate-400 px-1 text-[10px] font-semibold uppercase">GATE TEST:</span>
            <button
              onClick={() => setOutcome('VERIFIED')}
              className={`px-2.5 py-1 rounded-md text-xs font-bold transition-all ${
                outcome === 'VERIFIED'
                  ? 'bg-emerald-600 text-white shadow-xs'
                  : 'text-slate-500 hover:text-slate-200 dark:hover:text-slate-200'
              }`}
            >
              Pass Outcome
            </button>
            <button
              onClick={() => setOutcome('FAILED')}
              className={`px-2.5 py-1 rounded-md text-xs font-bold transition-all ${
                outcome === 'FAILED'
                  ? 'bg-rose-600 text-white shadow-xs'
                  : 'text-slate-500 hover:text-slate-200 dark:hover:text-slate-200'
              }`}
            >
              Fail Outcome
            </button>
          </div>

          <button
            onClick={handleRunSuite}
            disabled={isRunning}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500/100 disabled:opacity-50 text-white text-xs font-bold transition-all shadow-xs"
          >
            <Play size={13} className={isRunning ? 'animate-spin' : ''} />
            <span>{isRunning ? 'Running Replay...' : 'Run Sandbox Replay Now'}</span>
          </button>
        </div>
      </div>

      {/* Concept Explainer: What is Sandbox Verification */}
      <div className="rounded-xl border border-blue-200 dark:border-blue-900/50 bg-gradient-to-br from-blue-50/70 via-indigo-50/30 to-white dark:from-blue-950/30 dark:via-slate-900 dark:to-slate-900 p-5 shadow-2xs space-y-4">
        <div className="flex items-start gap-3">
          <div className="p-2 rounded-lg bg-blue-600 text-white shrink-0 mt-0.5 shadow-xs">
            <Cpu size={18} />
          </div>
          <div className="space-y-1">
            <h3 className="text-xs font-bold text-blue-950 dark:text-blue-200 uppercase tracking-wider flex items-center gap-2">
              <span>What is Sandbox Verification & How Does ORACLE Prove It?</span>
              <span className="text-[10px] normal-case font-normal px-2 py-0.5 rounded-full bg-blue-100 dark:bg-blue-900/60 text-blue-700 dark:text-blue-300">
                Zero-Trust Empirical Proof
              </span>
            </h3>
            <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
              Before any proposed fix touches staging or production, ORACLE boots an ephemeral micro-container isolated from production, applies the patch, and executes rigorous test suites to establish mathematical and empirical certainty.
            </p>
          </div>
        </div>

        {/* The 4 Pillars of Proof Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 pt-1">
          <div className="p-3 rounded-lg border border-white/10 bg-slate-900/80 dark:bg-slate-900/80 space-y-1 shadow-2xs">
            <div className="flex items-center gap-2 text-indigo-600 dark:text-indigo-400">
              <Shield size={14} />
              <span className="text-[11px] font-bold">1. Negative Proof</span>
            </div>
            <p className="text-[11px] text-slate-500 dark:text-slate-400">
              Replays exact failure condition. Proves bug <strong>no longer occurs</strong>.
            </p>
          </div>

          <div className="p-3 rounded-lg border border-white/10 bg-slate-900/80 dark:bg-slate-900/80 space-y-1 shadow-2xs">
            <div className="flex items-center gap-2 text-emerald-600 dark:text-emerald-400">
              <CheckCircle2 size={14} />
              <span className="text-[11px] font-bold">2. Zero Regressions</span>
            </div>
            <p className="text-[11px] text-slate-500 dark:text-slate-400">
              Executes full existing test suite (<strong>843 tests</strong>) with 0 failures.
            </p>
          </div>

          <div className="p-3 rounded-lg border border-white/10 bg-slate-900/80 dark:bg-slate-900/80 space-y-1 shadow-2xs">
            <div className="flex items-center gap-2 text-amber-600 dark:text-amber-400">
              <Code2 size={14} />
              <span className="text-[11px] font-bold">3. Scope Containment</span>
            </div>
            <p className="text-[11px] text-slate-500 dark:text-slate-400">
              AST analysis verifies only 2 target files modified; 0 unexpected leaks.
            </p>
          </div>

          <div className="p-3 rounded-lg border border-white/10 bg-slate-900/80 dark:bg-slate-900/80 space-y-1 shadow-2xs">
            <div className="flex items-center gap-2 text-purple-600 dark:text-purple-400">
              <Lock size={14} />
              <span className="text-[11px] font-bold">4. Signed Attestation</span>
            </div>
            <p className="text-[11px] text-slate-500 dark:text-slate-400">
              Binds patch SHA-256 and exit codes into a <strong>cryptographically signed seal</strong>.
            </p>
          </div>
        </div>
      </div>

      {/* Step-by-Step 5-Stage Replay Stepper */}
      <div className="p-5 rounded-xl border border-white/10 bg-slate-900/80 shadow-2xs space-y-3">
        <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
          5-Stage Sandbox Pipeline Progress
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
          {[
            { step: 1, label: '1. Container Boot', sub: 'Isolated Micro-VM' },
            { step: 2, label: '2. Apply Git Patch', sub: 'AST Scope Validation' },
            { step: 3, label: '3. Replay Failure', sub: 'Negative Assertion' },
            { step: 4, label: '4. Regression Suite', sub: '843 Tests Passed' },
            { step: 5, label: '5. Attestation Sealed', sub: 'SHA-256 Token' },
          ].map((s) => {
            const isDone = replayPhase >= s.step || (!isRunning && outcome === 'VERIFIED');
            const isActive = isRunning && replayPhase === s.step;
            return (
              <div
                key={s.step}
                className={`p-2.5 rounded-lg border text-xs transition-all ${
                  isDone
                    ? 'bg-emerald-500/10/80 border-emerald-300 dark:bg-emerald-950/30 dark:border-emerald-800/60 text-emerald-900 dark:text-emerald-200'
                    : isActive
                    ? 'bg-indigo-500/10 border-indigo-400 dark:bg-indigo-950/40 dark:border-indigo-700 text-indigo-900 dark:text-indigo-200 ring-2 ring-indigo-500/20'
                    : 'bg-slate-950/60 border-white/10 dark:bg-slate-800/40 dark:border-slate-800 text-slate-400 dark:text-slate-500'
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

      {/* Deployment Gate Banner */}
      {outcome === 'VERIFIED' ? (
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
                Original failure path eliminated. 843 regression tests passed with 0 side effects. Attestation sealed.
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
                1 regression test failed (deadlock in mutex_manager.py). Safe rollout gate locked.
              </p>
            </div>
          </div>
          <span className="text-xs font-bold px-3.5 py-1.5 rounded-lg bg-rose-600 text-white shrink-0 shadow-xs font-mono">
            DEPLOYMENT_BLOCKED
          </span>
        </div>
      )}

      {/* Artifact Inspector */}
      <div className="rounded-xl border border-white/10 bg-slate-900/80 shadow-2xs overflow-hidden">
        <div className="px-4 py-3 border-b border-white/10 flex items-center justify-between bg-slate-950/60/50 dark:bg-slate-800/30">
          <span className="text-xs font-bold text-white font-heading font-bold uppercase tracking-wider">
            Empirical Proof Artifacts
          </span>

          <div className="flex items-center gap-1 bg-slate-200/70 dark:bg-slate-800 p-1 rounded-lg text-xs font-medium">
            <button
              onClick={() => setActiveArtifactTab('OUTPUT')}
              className={`px-3 py-1 rounded-md transition-all ${
                activeArtifactTab === 'OUTPUT' ? 'bg-slate-900/80 text-white font-heading font-bold shadow-xs font-bold' : 'text-slate-600 dark:text-slate-400'
              }`}
            >
              Terminal Output
            </button>
            <button
              onClick={() => setActiveArtifactTab('TEST_CODE')}
              className={`px-3 py-1 rounded-md transition-all ${
                activeArtifactTab === 'TEST_CODE' ? 'bg-slate-900/80 text-white font-heading font-bold shadow-xs font-bold' : 'text-slate-600 dark:text-slate-400'
              }`}
            >
              Reproducer Test
            </button>
            <button
              onClick={() => setActiveArtifactTab('DIFF')}
              className={`px-3 py-1 rounded-md transition-all ${
                activeArtifactTab === 'DIFF' ? 'bg-slate-900/80 text-white font-heading font-bold shadow-xs font-bold' : 'text-slate-600 dark:text-slate-400'
              }`}
            >
              Unified Git Patch
            </button>
            <button
              onClick={() => setActiveArtifactTab('SCOPE')}
              className={`px-3 py-1 rounded-md transition-all ${
                activeArtifactTab === 'SCOPE' ? 'bg-slate-900/80 text-white font-heading font-bold shadow-xs font-bold' : 'text-slate-600 dark:text-slate-400'
              }`}
            >
              Scope Analysis
            </button>
            <button
              onClick={() => setActiveArtifactTab('CERTIFICATE')}
              className={`px-3 py-1 rounded-md transition-all ${
                activeArtifactTab === 'CERTIFICATE' ? 'bg-slate-900/80 text-white font-heading font-bold shadow-xs font-bold' : 'text-slate-600 dark:text-slate-400'
              }`}
            >
              Signed Certificate
            </button>
          </div>
        </div>

        {activeArtifactTab === 'OUTPUT' && (
          <div className="p-4 space-y-3">
            <div className="flex items-center justify-between text-xs text-slate-500 font-mono">
              <span>Execution Command: {investigation.verification?.testCommand || 'pytest tests/ -v'}</span>
              <button
                onClick={downloadTerminalLogs}
                className="flex items-center gap-1 px-2 py-1 rounded bg-slate-800/60 text-[11px] hover:bg-slate-200 dark:hover:bg-slate-700 transition-all cursor-pointer"
              >
                <Download size={11} />
                <span>Download Logs</span>
              </button>
            </div>
            <pre className="p-4 rounded-xl bg-slate-950 text-slate-200 font-mono text-xs overflow-x-auto leading-relaxed border border-slate-800 max-h-80 shadow-inner whitespace-pre-wrap">
              {investigation.verification?.terminalOutput ||
                (outcome === 'VERIFIED'
                  ? `$ pytest tests/test_payment_remediation.py tests/regression/ -v

============================= test session starts ==============================
platform linux -- Python 3.11.9, pytest-8.1.1
rootdir: /app/payment-api
collected 843 items

tests/test_payment_remediation.py::test_payment_failure_regression_legacy_fallback PASSED [  0%]
tests/regression/test_suite.py::test_regression_suite_pass [842 tests]            PASSED [100%]

============================== 843 passed in 18.42s ============================
Exit code: 0

VERIFICATION RESULT: ALL CHECKS PASSED
CRYPTOGRAPHIC SEAL: ATTEST-SHA256-10429a8f4c2e`
                  : `$ pytest tests/test_payment_remediation.py tests/regression/ -v

============================= test session starts ==============================
platform linux -- Python 3.11.9, pytest-8.1.1
collected 843 items

tests/test_payment_remediation.py::test_payment_failure_regression_legacy_fallback PASSED [  0%]
tests/regression/test_mutex.py::test_concurrent_checkout_lock FAILED              [ 98%]

=================================== FAILURES ===================================
Deadlock detected during concurrent lock acquisition in mutex_manager.py:42
=========================== 1 failed, 842 passed in 14.12s =====================
Exit code: 1`)}
            </pre>
          </div>
        )}

        {activeArtifactTab === 'TEST_CODE' && (
          <div className="p-4 space-y-3">
            <pre className="p-4 rounded-xl bg-slate-950 text-emerald-300 font-mono text-xs overflow-x-auto leading-relaxed border border-slate-800 max-h-80 shadow-inner">
              {investigation.verification?.testScript || `# tests/test_payment_remediation.py
import pytest
from unittest.mock import MagicMock
from src.customer.repository import CustomerRepository

def test_payment_failure_regression_legacy_fallback():
    mock_redis = MagicMock()
    mock_redis.get.side_effect = lambda k: b'{"id": "cust_99214", "is_active_subscriber": true}' if "user:cust:" in k else None
    
    repo = CustomerRepository(cache=mock_redis)
    customer = repo.get_customer("cust_99214")
    
    assert customer is not None, "Failed to retrieve customer under legacy namespace"
    assert customer.is_active_subscriber is True`}
            </pre>
          </div>
        )}

        {activeArtifactTab === 'DIFF' && (
          <div className="p-4 space-y-3">
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

        {activeArtifactTab === 'SCOPE' && (
          <div className="p-6 space-y-4 font-sans text-xs">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div className="p-3 rounded-lg border border-white/10 bg-slate-950/60/50 dark:bg-slate-800/30">
                <span className="text-[11px] font-semibold text-slate-400 block uppercase">Scope Boundary</span>
                <span className="text-sm font-bold text-emerald-600 dark:text-emerald-400 flex items-center gap-1 mt-1">
                  <CheckCircle2 size={14} />
                  {investigation.verification?.scopeContained !== false ? 'STRICTLY BOUNDED' : 'BOUNDARY VIOLATION'}
                </span>
              </div>
              <div className="p-3 rounded-lg border border-white/10 bg-slate-950/60/50 dark:bg-slate-800/30">
                <span className="text-[11px] font-semibold text-slate-400 block uppercase">Files Changed</span>
                <span className="text-sm font-mono font-bold text-slate-200 dark:text-slate-200 block mt-1">
                  {investigation.verification?.diffSummary?.filesChanged ?? ((investigation.verification as any)?.changedFilesCount || 2)} file(s) (+{investigation.verification?.diffSummary?.insertions || 4} / -{investigation.verification?.diffSummary?.deletions || 1})
                </span>
              </div>
              <div className="p-3 rounded-lg border border-white/10 bg-slate-950/60/50 dark:bg-slate-800/30">
                <span className="text-[11px] font-semibold text-slate-400 block uppercase">AST Structural Invariant</span>
                <span className="text-sm font-bold text-emerald-600 dark:text-emerald-400 flex items-center gap-1 mt-1">
                  <CheckCircle2 size={14} />
                  0 Syntax / Contract Errors
                </span>
              </div>
            </div>

            <div className="space-y-2">
              <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider block">
                Modified Files vs Resolution Plan Boundary
              </span>
              <div className="p-3 rounded-lg border border-white/10 bg-slate-950 font-mono text-xs text-slate-300 space-y-1.5">
                <div className="text-emerald-400 flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span>✓</span>
                    <span>src/payment/payment_service.py</span>
                  </div>
                  <span className="text-[10px] px-1.5 py-0.2 rounded bg-emerald-950 border border-emerald-800 text-emerald-300">AUTHORIZED</span>
                </div>
                <div className="text-emerald-400 flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span>✓</span>
                    <span>tests/test_payment.py</span>
                  </div>
                  <span className="text-[10px] px-1.5 py-0.2 rounded bg-emerald-950 border border-emerald-800 text-emerald-300">AUTHORIZED</span>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeArtifactTab === 'CERTIFICATE' && (
          <div className="p-6">
            <div className="border border-emerald-300 dark:border-emerald-800/80 rounded-xl bg-gradient-to-br from-emerald-50/50 via-white to-slate-50 dark:from-emerald-950/20 dark:via-slate-900 dark:to-slate-900 p-6 shadow-xs space-y-4 font-mono text-xs">
              <div className="flex items-center justify-between pb-3 border-b border-emerald-500/30/60">
                <div className="flex items-center gap-2">
                  <Award size={22} className="text-emerald-600" />
                  <span className="font-extrabold text-sm text-white font-heading font-bold">
                    ORACLE Verification Certificate
                  </span>
                </div>
                <span className="px-2 py-0.5 rounded font-bold bg-emerald-100 text-emerald-800 dark:bg-emerald-900 dark:text-emerald-300">
                  {outcome === 'VERIFIED' ? 'FIX VERIFIED' : 'DEPLOYMENT BLOCKED'}
                </span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-[11px]">
                <div>
                  <span className="text-slate-400 block">ATTESTATION TOKEN:</span>
                  <span className="font-bold text-white font-heading font-bold break-all">
                    {investigation.verification?.attestation?.token || 'ATTEST-SHA256-10429a8f4c2e710b89d4'}
                  </span>
                </div>
                <div>
                  <span className="text-slate-400 block">PATCH SHA-256:</span>
                  <span className="text-slate-300 dark:text-slate-300 break-all">
                    {investigation.verification?.attestation?.digest || '7d8a9b2c3e4f5061728394a5b6c7d8e9f0123456789abcdef0123456789abcde'}
                  </span>
                </div>
                <div>
                  <span className="text-slate-400 block">CONTAINER ID:</span>
                  <span className="text-slate-300 dark:text-slate-300">
                    {investigation.verification?.attestation?.containerId || 'sandbox-orc-inc-1042-microvm-04'}
                  </span>
                </div>
                <div>
                  <span className="text-slate-400 block">SIGNER AUTHORITY:</span>
                  <span className="text-slate-300 dark:text-slate-300">
                    {investigation.verification?.attestation?.signer || 'oracle-sandbox-engine/v5.1 (Ed25519)'}
                  </span>
                </div>

                {investigation.verification?.attestation?.signatureHex && (
                  <div className="sm:col-span-2 pt-2 border-t border-emerald-500/30/60">
                    <span className="text-slate-400 block">ED25519 DIGITAL SIGNATURE:</span>
                    <span className="font-mono text-[10px] text-emerald-300 break-all select-all">
                      {investigation.verification.attestation.signatureHex}
                    </span>
                  </div>
                )}
                {investigation.verification?.attestation?.publicKeyHex && (
                  <div className="sm:col-span-2">
                    <span className="text-slate-400 block">SIGNER PUBLIC KEY:</span>
                    <span className="font-mono text-[10px] text-slate-600 dark:text-slate-400 break-all select-all">
                      {investigation.verification.attestation.publicKeyHex}
                    </span>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
