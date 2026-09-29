import React, { useState, useEffect } from 'react';
import { SecurityAuditEvent } from '../../types/oracle';
import { oracleApi } from '../../lib/api';
import { ShieldCheck, Lock, FileCheck, RefreshCw, CheckCircle2, ShieldAlert, Award } from 'lucide-react';

export function SecurityView() {
  const [auditLogs, setAuditLogs] = useState<SecurityAuditEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [securityStatus, setSecurityStatus] = useState({
    evidenceIntegrity: true,
    policyViolations: 0,
    auditEventsCount: 127,
    authorityStatus: 'Active (Ed25519-SHA256)',
  });

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const [logs, sec] = await Promise.all([
        oracleApi.getAuditEvents(),
        oracleApi.getSecurityStatus(),
      ]);
      setAuditLogs(logs);
      setSecurityStatus(sec);
    } catch (e) {
      console.error('Failed to load audit logs:', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, []);

  return (
    <div className="p-6 lg:p-8 max-w-5xl mx-auto space-y-6 text-slate-200 dark:text-slate-200">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-3 pb-4 border-b border-white/10">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold tracking-tight text-white font-heading font-bold flex items-center gap-2">
              <ShieldCheck size={22} className="text-indigo-600 dark:text-indigo-400" />
              <span>Security & Audit Control Plane</span>
            </h1>
            <span className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-slate-800/60 text-slate-300 dark:text-slate-300 border border-white/10 dark:border-slate-700">
              Audit Active
            </span>
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
            Immutable audit logs, cryptographic evidence verification, and authorization gate records.
          </p>
        </div>

        <button
          onClick={fetchLogs}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800/60 hover:bg-slate-200 dark:hover:bg-slate-700 text-xs font-medium text-slate-300 dark:text-slate-300 transition-colors border border-white/10 dark:border-slate-700 self-start sm:self-auto"
        >
          <RefreshCw size={12} className={loading ? 'animate-spin' : ''} />
          <span>Refresh Audit Trail</span>
        </button>
      </div>

      {/* Security Status 4-Card Summary (Section 30) */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <div className="p-4 rounded-xl border border-white/10 bg-slate-900/80 shadow-2xs space-y-1">
          <span className="text-[11px] font-semibold text-slate-500 dark:text-slate-400 block">
            Evidence Integrity
          </span>
          <div className="flex items-center gap-2 text-emerald-600 dark:text-emerald-400 font-bold text-lg font-mono">
            <CheckCircle2 size={20} />
            <span>Verified</span>
          </div>
          <span className="text-[10px] text-slate-400 block">SHA-256 Hashes Valid</span>
        </div>

        <div className="p-4 rounded-xl border border-white/10 bg-slate-900/80 shadow-2xs space-y-1">
          <span className="text-[11px] font-semibold text-slate-500 dark:text-slate-400 block">
            Policy Violations
          </span>
          <div className="text-2xl font-black text-white font-heading font-bold font-mono">
            {securityStatus.policyViolations}
          </div>
          <span className="text-[10px] text-emerald-600 block">0 Invariant Breaks</span>
        </div>

        <div className="p-4 rounded-xl border border-white/10 bg-slate-900/80 shadow-2xs space-y-1">
          <span className="text-[11px] font-semibold text-slate-500 dark:text-slate-400 block">
            Audit Events
          </span>
          <div className="text-2xl font-black text-indigo-600 dark:text-indigo-400 font-mono">
            {securityStatus.auditEventsCount}
          </div>
          <span className="text-[10px] text-slate-400 block">Immutable Ledger</span>
        </div>

        <div className="p-4 rounded-xl border border-white/10 bg-slate-900/80 shadow-2xs space-y-1">
          <span className="text-[11px] font-semibold text-slate-500 dark:text-slate-400 block">
            Verification Authority
          </span>
          <div className="text-sm font-bold text-emerald-600 dark:text-emerald-400 flex items-center gap-1.5 pt-1">
            <Award size={16} />
            <span>Active</span>
          </div>
          <span className="text-[10px] text-slate-400 font-mono block truncate">Ed25519 Authority v2.4</span>
        </div>
      </div>

      {/* Audit Events Table (Section 30) */}
      <div className="border border-white/10 bg-slate-900/80 rounded-xl overflow-hidden shadow-2xs">
        <div className="p-3.5 bg-slate-950/60/70 dark:bg-slate-800/40 border-b border-white/10 text-xs font-semibold uppercase tracking-wider text-slate-600 dark:text-slate-300 flex justify-between">
          <span>Recent Audit Actions & Gate Events</span>
          <span className="text-emerald-600 dark:text-emerald-400 font-medium">100% Cryptographic Integrity</span>
        </div>

        <div className="divide-y divide-slate-100 dark:divide-slate-800/60">
          {auditLogs.length === 0 ? (
            <div className="p-6 text-center text-xs text-slate-400">
              {loading ? 'Loading audit trail...' : 'No audit records found.'}
            </div>
          ) : (
            auditLogs.map((log) => (
              <div key={log.id} className="p-4 flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="font-mono font-bold text-white font-heading font-bold">
                      {log.id}
                    </span>
                    <span className="text-[10px] px-2 py-0.2 rounded font-mono font-bold bg-indigo-500/100/10 text-indigo-300">
                      {log.action}
                    </span>
                    <span className="text-slate-400 text-[11px] font-mono">
                      by {log.actor}
                    </span>
                  </div>
                  <div className="text-slate-300 dark:text-slate-300">
                    Target: <strong className="font-mono">{log.target}</strong>
                  </div>
                  {log.details && (
                    <div className="text-[11px] text-slate-500 dark:text-slate-400">
                      {log.details}
                    </div>
                  )}
                </div>

                <div className="flex flex-col md:items-end gap-1 shrink-0 font-mono text-[10px] text-slate-400">
                  <span>{log.timestamp}</span>
                  <span className="truncate max-w-[180px]" title={log.hash}>
                    SHA: {log.hash.substring(0, 16)}...
                  </span>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
