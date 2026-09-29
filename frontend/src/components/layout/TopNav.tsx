import React, { useState } from 'react';
import { Search, Plus, Radio, Activity, Cpu, HelpCircle, X, CheckCircle2, ArrowRight, ShieldCheck, Sparkles, Terminal } from 'lucide-react';
import { SeverityBadge, StageBadge } from '../common/Badges';
import { IncidentInvestigation } from '../../types/oracle';
import { audioFx } from '../../lib/audio';

interface TopNavProps {
  currentTab: string;
  activeIncident: IncidentInvestigation;
  allIncidents: IncidentInvestigation[];
  onSelectIncident: (incident: IncidentInvestigation) => void;
  onOpenCommandPalette: () => void;
  onStartNewInvestigation: () => void;
  onNavigate: (tab: string) => void;
}

export function TopNav({
  currentTab,
  activeIncident,
  allIncidents,
  onSelectIncident,
  onOpenCommandPalette,
  onStartNewInvestigation,
  onNavigate,
}: TopNavProps) {
  const [showGuideModal, setShowGuideModal] = useState(false);

  return (
    <>
      <header className="h-14 border-b border-sky-500/20 bg-[#080d1a]/95 backdrop-blur-xl flex items-center justify-between px-4 sm:px-6 z-20 select-none text-xs text-slate-200">
        {/* Left: Brand & Incident Picker */}
        <div className="flex items-center gap-3 min-w-0">
          <button
            onClick={() => {
              audioFx.click();
              onNavigate('overview');
            }}
            className="flex items-center gap-2 hover:opacity-90 transition-opacity font-bold tracking-tight text-white"
          >
            <div className="w-6 h-6 rounded-md bg-gradient-to-tr from-sky-500 to-indigo-600 flex items-center justify-center text-white shadow-[0_0_12px_rgba(56,189,248,0.4)]">
              <Cpu className="w-3.5 h-3.5" />
            </div>
            <span className="font-heading font-extrabold text-sm tracking-tight gradient-text">ORACLE</span>
          </button>

          <button
            onClick={() => {
              audioFx.click();
              onNavigate('landing');
            }}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-semibold text-neutral-300 hover:text-white bg-neutral-800/80 hover:bg-neutral-800 border border-neutral-700/60 transition-colors shrink-0"
          >
            ← Landing Page
          </button>
          
          <span className="text-slate-600">/</span>
          <span className="text-slate-400 capitalize font-medium hidden sm:inline">
            {currentTab.replace('-', ' ')}
          </span>
          <span className="text-slate-600 hidden sm:inline">/</span>

          {/* Active Incident Dropdown Selector */}
          <div className="flex items-center gap-2 min-w-0">
            <select
              value={activeIncident.id}
              onChange={(e) => {
                audioFx.click();
                const selected = allIncidents.find((i) => i.id === e.target.value);
                if (selected) {
                  onSelectIncident(selected);
                }
              }}
              aria-label="Select incident"
              className="bg-slate-900/90 border border-sky-500/30 text-sky-200 font-mono text-xs font-semibold px-2.5 py-1 rounded-md focus:outline-none focus:border-sky-400 cursor-pointer max-w-[170px] sm:max-w-xs truncate shadow-[0_0_12px_rgba(56,189,248,0.15)] hover:border-sky-400/60 transition-colors"
            >
              {allIncidents.map((inc) => (
                <option key={inc.id} value={inc.id} className="bg-slate-950 text-slate-200">
                  {inc.id} — {inc.service}
                </option>
              ))}
            </select>

            <SeverityBadge severity={activeIncident.severity} />
            <div className="hidden md:inline-flex">
              <StageBadge stage={activeIncident.stage} />
            </div>
          </div>
        </div>

        {/* Right: Actions & How It Works */}
        <div className="flex items-center gap-2.5">
          {/* How It Works Guide Trigger */}
          <button
            onClick={() => {
              audioFx.click();
              setShowGuideModal(true);
            }}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-indigo-500/10 hover:bg-indigo-500/20 border border-indigo-400/30 text-indigo-300 transition-all text-xs font-medium"
            title="Understand how ORACLE works end-to-end"
          >
            <HelpCircle className="w-3.5 h-3.5 text-indigo-400" />
            <span className="hidden md:inline">How It Works</span>
          </button>

          {/* Live Control Plane Status Beacon */}
          <div className="hidden lg:flex items-center gap-2 px-2.5 py-1 rounded-md bg-emerald-950/40 border border-emerald-500/30 text-[11px] text-emerald-400 shadow-[0_0_12px_rgba(16,185,129,0.15)]">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
            </span>
            <span className="font-semibold tracking-wider font-mono">LIVE CONTROL PLANE</span>
          </div>

          {/* Quick Search */}
          <button
            onClick={() => {
              audioFx.click();
              onOpenCommandPalette();
            }}
            className="flex items-center gap-2 px-2.5 py-1 rounded-md bg-slate-900 border border-white/10 hover:border-sky-500/40 text-slate-400 hover:text-sky-300 transition-colors text-xs font-mono"
          >
            <Search className="w-3.5 h-3.5 text-sky-400" />
            <span className="hidden sm:inline">Search</span>
            <kbd className="text-[10px] bg-black/60 px-1 rounded border border-white/10 text-slate-400">⌘K</kbd>
          </button>

          {/* New Investigation button */}
          <button
            onClick={() => {
              audioFx.click();
              onStartNewInvestigation();
            }}
            className="gradient-border-btn flex items-center gap-1.5 px-3 py-1.5 rounded-md font-['Plus_Jakarta_Sans'] text-xs font-bold transition-all shadow-md"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>New Investigation</span>
          </button>
        </div>
      </header>

      {/* Interactive 'How ORACLE Works' Modal */}
      {showGuideModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-md">
          <div className="relative w-full max-w-2xl bg-[#0b1222] border border-sky-500/40 rounded-xl shadow-[0_0_50px_rgba(56,189,248,0.25)] p-6 space-y-6 text-slate-200">
            {/* Modal Header */}
            <div className="flex items-center justify-between pb-4 border-b border-white/10">
              <div className="flex items-center gap-2.5">
                <div className="w-8 h-8 rounded-lg bg-sky-500/20 border border-sky-500/40 flex items-center justify-center text-sky-400">
                  <Sparkles className="w-4 h-4" />
                </div>
                <div>
                  <h3 className="font-['Plus_Jakarta_Sans'] font-bold text-base text-white">How ORACLE Works (End-to-End)</h3>
                  <p className="text-xs text-slate-400">Autonomous AI Detective and Verification Gate for production code incidents.</p>
                </div>
              </div>
              <button
                onClick={() => setShowGuideModal(false)}
                className="text-slate-400 hover:text-white p-1 rounded-md"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* 5-Step Story */}
            <div className="space-y-3.5 text-xs">
              <div className="flex items-start gap-3 p-3 rounded-lg bg-slate-900/80 border border-white/5">
                <span className="font-mono text-sky-400 font-bold px-2 py-0.5 rounded bg-sky-950/60 border border-sky-800">01</span>
                <div>
                  <strong className="text-white block font-['Plus_Jakarta_Sans'] font-semibold">Incident Ingestion</strong>
                  <p className="text-slate-400 mt-0.5">CloudWatch or Datadog alerts trigger ORACLE when error spikes occur (e.g. 500 errors on payment-api).</p>
                </div>
              </div>

              <div className="flex items-start gap-3 p-3 rounded-lg bg-slate-900/80 border border-white/5">
                <span className="font-mono text-indigo-400 font-bold px-2 py-0.5 rounded bg-indigo-950/60 border border-indigo-800">02</span>
                <div>
                  <strong className="text-white block font-['Plus_Jakarta_Sans'] font-semibold">Evidence Room Collection</strong>
                  <p className="text-slate-400 mt-0.5">Automatically indexes git commits, recent pull requests (PR #284), error stack traces, and Redis telemetry.</p>
                </div>
              </div>

              <div className="flex items-start gap-3 p-3 rounded-lg bg-slate-900/80 border border-white/5">
                <span className="font-mono text-amber-400 font-bold px-2 py-0.5 rounded bg-amber-950/60 border border-amber-800">03</span>
                <div>
                  <strong className="text-white block font-['Plus_Jakarta_Sans'] font-semibold">Hypothesis Testing &amp; Root Cause</strong>
                  <p className="text-slate-400 mt-0.5">Evaluates competing theories. Confirms the Redis cache key namespace mismatch with 94% confidence.</p>
                </div>
              </div>

              <div className="flex items-start gap-3 p-3 rounded-lg bg-slate-900/80 border border-white/5">
                <span className="font-mono text-purple-400 font-bold px-2 py-0.5 rounded bg-purple-950/60 border border-purple-800">04</span>
                <div>
                  <strong className="text-white block font-['Plus_Jakarta_Sans'] font-semibold">Agent Task Prompt Formulation</strong>
                  <p className="text-slate-400 mt-0.5">Synthesizes guarded instructions and code diff requirements for an AI coding assistant (Cursor, Claude Code, Aider).</p>
                </div>
              </div>

              <div className="flex items-start gap-3 p-3 rounded-lg bg-slate-900/80 border border-white/5">
                <span className="font-mono text-emerald-400 font-bold px-2 py-0.5 rounded bg-emerald-950/60 border border-emerald-800">05</span>
                <div>
                  <strong className="text-white block font-['Plus_Jakarta_Sans'] font-semibold">Sandbox Verification &amp; Release Gate</strong>
                  <p className="text-slate-400 mt-0.5">Never trusts code blindly. Replays traffic in an isolated sandbox, verifies regression tests, and clears the release gate.</p>
                </div>
              </div>
            </div>

            {/* Modal Footer */}
            <div className="flex items-center justify-between pt-3 border-t border-white/10">
              <span className="text-[11px] text-slate-400">Explore the sub-tabs in <strong>Investigations</strong> to see each step live!</span>
              <button
                onClick={() => setShowGuideModal(false)}
                className="px-4 py-1.5 rounded-md bg-sky-500 hover:bg-sky-400 text-slate-950 font-bold text-xs"
              >
                Got It, Let&apos;s Investigate
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
