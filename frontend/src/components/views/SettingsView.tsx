import React, { useState, useEffect } from 'react';
import { oracleApi, ApiMode } from '../../lib/api';
import { Database, RefreshCw, CheckCircle2, AlertCircle, Save, Server, ShieldCheck, ToggleLeft, ToggleRight } from 'lucide-react';

interface SettingsViewProps {
  onModeChange: () => void;
}

export function SettingsView({ onModeChange }: SettingsViewProps) {
  const [apiUrl, setApiUrl] = useState<string>(oracleApi.getBaseUrl());
  const [apiMode, setApiMode] = useState<ApiMode>(oracleApi.getMode());
  const [testStatus, setTestStatus] = useState<string | null>(null);
  const [persistenceType, setPersistenceType] = useState<string>('SQLite');
  const [testing, setTesting] = useState(false);
  const [savedSuccess, setSavedSuccess] = useState(false);

  useEffect(() => {
    oracleApi.getHealth().then((h) => {
      setPersistenceType(h.persistence);
      setApiMode(h.mode);
    });
  }, []);

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    oracleApi.setBaseUrl(apiUrl);
    oracleApi.setMode(apiMode);
    onModeChange();
    setSavedSuccess(true);
    setTimeout(() => setSavedSuccess(false), 2500);
  };

  const handleTestConnection = async () => {
    setTesting(true);
    setTestStatus(null);
    try {
      const res = await oracleApi.getHealth();
      setPersistenceType(res.persistence);
      setTestStatus(`Connected successfully! Status: ${res.status}, Latency: ${res.latencyMs}ms, Persistence: ${res.persistence}`);
    } catch (err: any) {
      setTestStatus(`Connection error: ${err.message || 'Failed to connect to backend endpoint'}`);
    } finally {
      setTesting(false);
    }
  };

  return (
    <div className="p-6 lg:p-8 max-w-4xl mx-auto space-y-6 text-slate-200 dark:text-slate-200">
      <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-3 pb-4 border-b border-white/10">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold tracking-tight text-white font-heading font-bold">
              Settings & Backend Integration
            </h1>
            <span className={`text-[11px] font-mono px-2 py-0.5 rounded-full border ${
              apiMode === 'REAL'
                ? 'bg-emerald-500/10 text-emerald-700 border-emerald-300 dark:bg-emerald-950/40 dark:text-emerald-300 dark:border-emerald-800'
                : 'bg-amber-500/10 text-amber-700 border-amber-300 dark:bg-amber-950/40 dark:text-amber-300 dark:border-amber-800'
            }`}>
              {apiMode === 'REAL' ? '● LIVE FASTAPI BACKEND' : '● MOCK MODE (DEMO)'}
            </span>
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
            Configure live FastAPI connectivity or switch to local offline demonstration mode.
          </p>
        </div>
      </div>

      <form onSubmit={handleSave} className="space-y-6">
        {/* Mode Selector Card (Section 27) */}
        <div className="border border-white/10 bg-slate-900/80 rounded-xl p-5 space-y-3 shadow-2xs">
          <div className="flex items-center justify-between pb-2 border-b border-white/10">
            <div>
              <span className="text-xs font-bold uppercase tracking-wider text-slate-300 dark:text-slate-300 block">
                Execution Mode
              </span>
              <p className="text-[11px] text-slate-500 dark:text-slate-400">
                Switch between live Python/FastAPI backend and offline realistic mock mode.
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-1">
            <div
              onClick={() => setApiMode('REAL')}
              className={`p-4 rounded-xl border cursor-pointer transition-all space-y-1 ${
                apiMode === 'REAL'
                  ? 'bg-emerald-500/10/70 border-emerald-400 dark:bg-emerald-950/30 dark:border-emerald-700 shadow-xs'
                  : 'bg-slate-950/60 dark:bg-slate-800/40 border-white/10 hover:border-white/15'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-white font-heading font-bold">
                  Live FastAPI Control Plane
                </span>
                {apiMode === 'REAL' && <CheckCircle2 size={16} className="text-emerald-600 dark:text-emerald-400" />}
              </div>
              <p className="text-[11px] text-slate-500 dark:text-slate-400">
                Connects directly to http://localhost:8000/api/v1 with durable SQLite persistence.
              </p>
            </div>

            <div
              onClick={() => setApiMode('MOCK')}
              className={`p-4 rounded-xl border cursor-pointer transition-all space-y-1 ${
                apiMode === 'MOCK'
                  ? 'bg-amber-500/10/70 border-amber-400 dark:bg-amber-950/30 dark:border-amber-700 shadow-xs'
                  : 'bg-slate-950/60 dark:bg-slate-800/40 border-white/10 hover:border-white/15'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-white font-heading font-bold">
                  Mock Mode (Offline Demo)
                </span>
                {apiMode === 'MOCK' && <CheckCircle2 size={16} className="text-amber-600 dark:text-amber-400" />}
              </div>
              <p className="text-[11px] text-slate-500 dark:text-slate-400">
                Operates without backend using realistic canonical INC-1042 data with labeled demo artifacts.
              </p>
            </div>
          </div>
        </div>

        {/* Backend Endpoint Card */}
        <div className="border border-white/10 bg-slate-900/80 rounded-xl p-5 space-y-4 shadow-2xs">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-300 dark:text-slate-300">
              API Connection Details
            </span>
            <span className="text-[11px] font-mono text-indigo-600 dark:text-indigo-400">
              Target: {apiUrl}
            </span>
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-medium text-slate-300 dark:text-slate-300 flex items-center justify-between">
              <span>FastAPI Backend Base URL (VITE_ORACLE_API_URL)</span>
              <span className="text-slate-400 text-[11px]">Default: http://localhost:8000/api/v1</span>
            </label>
            <div className="flex gap-2">
              <input
                type="text"
                value={apiUrl}
                onChange={(e) => setApiUrl(e.target.value)}
                placeholder="http://localhost:8000/api/v1"
                className="flex-1 bg-slate-900/80 border border-white/15 dark:border-slate-700 rounded-lg px-3.5 py-2 text-xs text-white dark:text-slate-100 focus:ring-2 focus:ring-indigo-500 font-mono"
              />
              <button
                type="button"
                onClick={handleTestConnection}
                disabled={testing}
                className="px-3.5 py-2 rounded-lg bg-slate-800/60 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-300 dark:text-slate-300 text-xs font-medium border border-white/10 dark:border-slate-700 transition-colors shrink-0 flex items-center gap-1.5"
              >
                <RefreshCw size={12} className={testing ? 'animate-spin' : ''} />
                <span>Test Live Ping</span>
              </button>
            </div>
            {testStatus && (
              <p className="text-xs text-emerald-600 dark:text-emerald-400 mt-1 font-mono">{testStatus}</p>
            )}
          </div>
        </div>

        {/* Action Button */}
        <div className="flex items-center justify-between pt-2">
          {savedSuccess ? (
            <span className="text-xs text-emerald-600 dark:text-emerald-400 flex items-center gap-1.5 font-semibold">
              <CheckCircle2 size={14} /> Configuration saved and updated in local state
            </span>
          ) : (
            <span className="text-xs text-slate-400">Settings persist in local browser storage.</span>
          )}

          <button
            type="submit"
            className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-slate-900 dark:bg-slate-900/80 text-white dark:text-white font-bold text-xs transition-all shadow-xs hover:bg-slate-800"
          >
            <Save size={14} />
            <span>Save Configuration</span>
          </button>
        </div>
      </form>
    </div>
  );
}
