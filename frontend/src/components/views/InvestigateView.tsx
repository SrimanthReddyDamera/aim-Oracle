import React, { useState } from 'react';
import { 
  Play, 
  Terminal, 
  Database, 
  GitBranch, 
  Server, 
  Activity, 
  FileCode2, 
  Layers,
  CheckSquare, 
  Square,
  Sparkles,
  ArrowRight,
  Clock,
  Cloud,
  FolderGit2,
  CheckCircle2,
  AlertCircle,
  RefreshCw,
  FileText
} from 'lucide-react';
import { inspectRepository } from '../../lib/api/investigations';

interface InvestigateViewProps {
  onStartInvestigation: (payload: {
    title: string;
    stackTrace: string;
    service: string;
    environment: string;
    repository: string;
    deployment: string;
    cloudProvider: string;
    timeRange: string;
    additionalNotes: string;
    selectedSources: string[];
    repository_path?: string;
    logs?: string;
  }) => void;
}

export function InvestigateView({ onStartInvestigation }: InvestigateViewProps) {
  // Preset selector
  const [activePreset, setActivePreset] = useState<string>('BUG_B');

  // Input states
  const [title, setTitle] = useState('Payment API returning 500 errors');
  const [service, setService] = useState('payment-api');
  const [environment, setEnvironment] = useState('Production');
  const [repository, setRepository] = useState('github.com/enterprise/payment-api');
  const [repositoryPath, setRepositoryPath] = useState('tests/test_repos/evaluation_repo');
  const [deployment, setDeployment] = useState('v2.14.2');
  const [cloudProvider, setCloudProvider] = useState('AWS us-east-1');
  const [incidentTime, setIncidentTime] = useState('14:28:11 UTC (Past 45 minutes)');
  const [additionalNotes, setAdditionalNotes] = useState('Spike in customer 500 errors on payment checkout completion after v2.14.2 rollout.');

  const [stackTrace, setStackTrace] = useState(`Traceback (most recent call last):
  File "src/payment/payment_service.py", line 184, in process_payment
    customer_tier = customer["tier"]
KeyError: 'Customer record missing from active cache session'
during handling of the above exception:
TypeError: 'NoneType' object is not subscriptable`);

  const [logs, setLogs] = useState(`2026-09-14T08:24:11.402Z [ERROR] payment-api payment_service.py:184: get_customer() returned None
2026-09-14T08:24:11.403Z [WARN] payment-api Redis MISS customers:8472
2026-09-14T08:24:11.404Z [ERROR] payment-api TypeError: 'NoneType' object is not subscriptable`);

  const [showLogs, setShowLogs] = useState(true);
  const [repoValidation, setRepoValidation] = useState<{
    valid?: boolean;
    info?: string;
    checking?: boolean;
  }>({ valid: true, info: 'Python • FastAPI • pytest • 6 files' });

  // Evidence sources
  const [sources, setSources] = useState<Record<string, boolean>>({
    'Logs': true,
    'Stack Trace': true,
    'Repository': true,
    'Git History': true,
    'Deployment History': false,
    'Metrics': false,
    'Configuration': true,
  });

  const toggleSource = (sourceName: string) => {
    setSources((prev) => ({
      ...prev,
      [sourceName]: !prev[sourceName],
    }));
  };

  const handleValidateRepo = async () => {
    if (!repositoryPath) return;
    setRepoValidation({ checking: true });
    try {
      const res = await inspectRepository(repositoryPath);
      const langs = res.inventory?.languages?.join(', ') || 'Code';
      const fws = res.inventory?.frameworks?.join(', ') || '';
      const total = res.inventory?.total_files || 0;
      setRepoValidation({
        valid: true,
        info: `${langs}${fws ? ' • ' + fws : ''} • ${total} files`,
        checking: false,
      });
    } catch (err: any) {
      setRepoValidation({
        valid: false,
        info: err.message || 'Directory outside allowed root or missing',
        checking: false,
      });
    }
  };

  const applyPreset = (presetKey: string) => {
    setActivePreset(presetKey);
    if (presetKey === 'BUG_B') {
      setTitle('Payment API returning 500 errors (Cache Key Mismatch)');
      setService('payment-api');
      setRepositoryPath('tests/test_repos/evaluation_repo');
      setStackTrace(`Traceback (most recent call last):
  File "src/payment/payment_service.py", line 184, in process_payment
    customer_tier = customer["tier"]
KeyError: 'Customer record missing from active cache session'
during handling of the above exception:
TypeError: 'NoneType' object is not subscriptable`);
      setLogs(`2026-09-14T08:24:11.402Z [ERROR] payment-api payment_service.py:184: get_customer() returned None
2026-09-14T08:24:11.403Z [WARN] payment-api Redis MISS customers:8472
2026-09-14T08:24:11.404Z [ERROR] payment-api TypeError: 'NoneType' object is not subscriptable`);
      setRepoValidation({ valid: true, info: 'Python • FastAPI • pytest • 6 files' });
    } else if (presetKey === 'BUG_A') {
      setTitle('Null pointer dereference during VIP payment processing');
      setService('payment-api');
      setRepositoryPath('tests/test_repos/evaluation_repo');
      setStackTrace(`Traceback (most recent call last):
  File "src/payment/payment_service.py", line 184, in process_payment
    customer_tier = customer["tier"]
TypeError: 'NoneType' object is not subscriptable`);
      setLogs(`2026-09-14T08:24:11.402Z [ERROR] payment-api process_payment: lookup_customer returned None`);
    } else if (presetKey === 'BUG_C') {
      setTitle('Upstream connection timeout during transaction settlement');
      setService('payment-api');
      setRepositoryPath('tests/test_repos/evaluation_repo');
      setStackTrace(`Traceback (most recent call last):
  File "src/payment/payment_service.py", line 184, in process_payment
TimeoutError: Redis connection timed out after 50ms`);
      setLogs(`2026-09-14T08:24:11.402Z [ERROR] payment-api Redis connection timeout: 50ms exceeded`);
    } else if (presetKey === 'BUG_D') {
      setTitle('Regression on checkout after commit 8f31a2');
      setService('payment-api');
      setRepositoryPath('tests/test_repos/evaluation_repo');
      setStackTrace(`Traceback (most recent call last):
  File "src/payment/payment_service.py", line 184, in process_payment
    customer_tier = customer["tier"]
TypeError: 'NoneType' object is not subscriptable`);
      setLogs(`2026-09-14T08:24:11.402Z [ERROR] payment-api TypeError in commit 8f31a2`);
    } else if (presetKey === 'BUG_E') {
      setTitle('Ambiguous transient degradation in unknown upstream caller');
      setService('payment-api');
      setRepositoryPath('tests/test_repos/evaluation_repo');
      setStackTrace(`Traceback (most recent call last):
  File "src/payment/nonexistent_gateway.py", line 99, in handle_call
    return dispatch()
RuntimeError: Network failure`);
      setLogs(`2026-09-14T08:24:11.402Z [WARN] network drop in external gateway`);
    } else if (presetKey === 'CANONICAL') {
      setTitle('Payment API returning 500 errors');
      setService('payment-api');
      setRepositoryPath('');
      setStackTrace(`2026-09-14T08:24:11.402Z [ERROR] payment_service.py:184: get_customer() returned None
Traceback (most recent call last):
  File "src/payment/payment_service.py", line 184, in process_payment
    customer = self.customer_repo.get_customer(customer_id)
  File "src/customer/repository.py", line 92, in get_customer
    data = self.cache.get(key)
KeyError: 'Customer record missing from active cache session'
during handling of the above exception:
AttributeError: 'NoneType' object has no attribute 'is_active_subscriber'`);
      setLogs('');
    }
  };

  const handleStart = (e: React.FormEvent) => {
    e.preventDefault();
    const selectedSources = Object.entries(sources)
      .filter(([_, enabled]) => enabled)
      .map(([name]) => name);

    onStartInvestigation({
      title,
      stackTrace,
      service,
      environment,
      repository,
      deployment,
      cloudProvider,
      timeRange: incidentTime,
      additionalNotes,
      selectedSources,
      repository_path: repositoryPath || undefined,
      logs: logs || undefined,
    });
  };

  return (
    <div className="p-6 lg:p-8 max-w-5xl mx-auto space-y-6 text-slate-200 dark:text-slate-200">
      {/* Header */}
      <div className="pb-3 border-b border-white/10">
        <h1 className="text-xl font-bold tracking-tight text-white font-heading font-bold flex items-center gap-2.5">
          <Terminal size={22} className="text-indigo-600 dark:text-indigo-400" />
          <span>Real Repository Intake & Incident Investigation</span>
        </h1>
        <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
          Ground ORACLE's empirical investigation engine in an actual codebase, error traceback, and production logs.
        </p>
      </div>

      {/* Preset Evaluation Scenarios Bar */}
      <div className="p-4 rounded-xl border border-indigo-500/30/80 dark:border-indigo-900/60 bg-indigo-500/10/40 dark:bg-indigo-950/20 space-y-2.5">
        <div className="flex items-center justify-between">
          <span className="text-xs font-bold uppercase tracking-wider text-indigo-900 dark:text-indigo-300 flex items-center gap-1.5">
            <Sparkles size={14} className="text-indigo-600 dark:text-indigo-400" />
            <span>Benchmark Evaluation Presets (Ground Truth Bugs A – E)</span>
          </span>
          <span className="text-[11px] text-indigo-600 dark:text-indigo-400 font-mono">1-Click Auto-Fill</span>
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2">
          {[
            { id: 'BUG_B', label: 'Bug B: Cache Key', desc: 'Namespace mismatch' },
            { id: 'BUG_A', label: 'Bug A: Null Prop', desc: 'NoneType subscript' },
            { id: 'BUG_C', label: 'Bug C: Timeout', desc: '50ms config mismatch' },
            { id: 'BUG_D', label: 'Bug D: Commit Regr', desc: 'Git commit 8f31a2' },
            { id: 'BUG_E', label: 'Bug E: Ambiguous', desc: 'Insufficient Evidence' },
            { id: 'CANONICAL', label: 'INC-1042 Baseline', desc: 'Demonstration run' },
          ].map((item) => (
            <button
              key={item.id}
              type="button"
              onClick={() => applyPreset(item.id)}
              className={`p-2.5 rounded-lg border text-left transition-all ${
                activePreset === item.id
                  ? 'border-indigo-600 bg-indigo-600 text-white shadow-xs font-bold'
                  : 'border-white/10 bg-slate-900/80 hover:border-indigo-400 text-slate-300 dark:text-slate-300'
              }`}
            >
              <div className="text-[11px] truncate">{item.label}</div>
              <div className={`text-[10px] truncate ${activePreset === item.id ? 'text-indigo-100' : 'text-slate-400'}`}>{item.desc}</div>
            </button>
          ))}
        </div>
      </div>

      <form onSubmit={handleStart} className="space-y-6">
        {/* Real Repository Registration Box */}
        <div className="p-5 rounded-xl border border-white/10 bg-slate-900/80 shadow-2xs space-y-4">
          <div className="flex items-center justify-between pb-2 border-b border-white/10">
            <label className="text-xs font-bold uppercase tracking-wider text-slate-300 dark:text-slate-300 flex items-center gap-2">
              <FolderGit2 size={16} className="text-indigo-600 dark:text-indigo-400" />
              <span>Real Repository Path (Security Sandboxed)</span>
            </label>
            {repoValidation.valid ? (
              <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-emerald-100 text-emerald-800 dark:bg-emerald-950/60 dark:text-emerald-300">
                <CheckCircle2 size={12} />
                <span>{repoValidation.info}</span>
              </span>
            ) : (
              <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-rose-100 text-rose-800 dark:bg-rose-950/60 dark:text-rose-300">
                <AlertCircle size={12} />
                <span>{repoValidation.info}</span>
              </span>
            )}
          </div>

          <div className="flex gap-2">
            <input
              type="text"
              value={repositoryPath}
              onChange={(e) => {
                setRepositoryPath(e.target.value);
                setRepoValidation({});
              }}
              placeholder="e.g. tests/test_repos/evaluation_repo or /workspace/my-service"
              className="flex-1 px-3.5 py-2.5 rounded-lg border border-white/15 dark:border-slate-700 bg-slate-950/80 text-white font-heading font-bold font-mono text-xs focus:ring-2 focus:ring-indigo-500 outline-hidden"
            />
            <button
              type="button"
              onClick={handleValidateRepo}
              disabled={repoValidation.checking}
              className="px-4 py-2.5 rounded-lg border border-white/15 dark:border-slate-700 bg-slate-800/60 hover:bg-slate-200 dark:hover:bg-slate-700 text-xs font-semibold flex items-center gap-1.5 transition-all"
            >
              <RefreshCw size={13} className={repoValidation.checking ? 'animate-spin' : ''} />
              <span>Validate Repo</span>
            </button>
          </div>
          <p className="text-[11px] text-slate-500 dark:text-slate-400">
            Enforces strict path traversal and symlink boundary sandboxing. Files outside allowed workspace roots are prohibited.
          </p>
        </div>

        {/* Incident Summary Input */}
        <div className="p-5 rounded-xl border border-white/10 bg-slate-900/80 shadow-2xs space-y-4">
          <div>
            <label className="text-xs font-bold uppercase tracking-wider text-slate-300 dark:text-slate-300 block mb-1">
              Incident Title / Summary *
            </label>
            <input
              type="text"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="e.g. Payment API returning 500 errors"
              required
              className="w-full px-3.5 py-2.5 rounded-lg border border-white/15 dark:border-slate-700 bg-slate-950/80 text-white font-heading font-bold font-medium text-xs focus:ring-2 focus:ring-indigo-500 outline-hidden"
            />
          </div>

          {/* Code / Log Stack Trace Editor */}
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label className="text-xs font-bold uppercase tracking-wider text-slate-300 dark:text-slate-300 flex items-center gap-1.5">
                <FileCode2 size={14} className="text-indigo-500" />
                <span>Error / Stack Trace *</span>
              </label>
              <span className="text-[11px] text-slate-400 font-mono">Multi-Runtime Traceback Parser</span>
            </div>
            <textarea
              rows={7}
              value={stackTrace}
              onChange={(e) => setStackTrace(e.target.value)}
              required
              className="w-full p-4 rounded-xl border border-slate-800 bg-slate-950 text-emerald-300 font-mono text-xs leading-relaxed focus:ring-2 focus:ring-indigo-500 outline-hidden shadow-inner"
            />
          </div>

          {/* Optional Production Logs Collapsible */}
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <button
                type="button"
                onClick={() => setShowLogs(!showLogs)}
                className="text-xs font-bold uppercase tracking-wider text-slate-300 dark:text-slate-300 flex items-center gap-1.5 hover:text-indigo-500 transition-colors"
              >
                <FileText size={14} className="text-indigo-500" />
                <span>Optional Production Logs / Telemetry Stream {showLogs ? '▼' : '▶'}</span>
              </button>
              <span className="text-[11px] text-slate-400 font-mono">Timestamp & Request ID Correlation</span>
            </div>
            {showLogs && (
              <textarea
                rows={4}
                value={logs}
                onChange={(e) => setLogs(e.target.value)}
                placeholder="Paste optional log output with timestamps or request IDs..."
                className="w-full p-3 rounded-xl border border-slate-800 bg-slate-950 text-amber-300 font-mono text-xs leading-relaxed focus:ring-2 focus:ring-indigo-500 outline-hidden shadow-inner"
              />
            )}
          </div>
        </div>

        {/* Context Fields (Section 4) */}
        <div className="p-5 rounded-xl border border-white/10 bg-slate-900/80 shadow-2xs space-y-4">
          <div className="text-xs font-bold uppercase tracking-wider text-slate-300 dark:text-slate-300 pb-2 border-b border-white/10">
            System & Environmental Context
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            <div>
              <label className="text-[11px] font-semibold text-slate-600 dark:text-slate-400 block mb-1">
                Service
              </label>
              <input
                type="text"
                value={service}
                onChange={(e) => setService(e.target.value)}
                required
                className="w-full px-3 py-2 rounded-lg border border-white/15 dark:border-slate-700 bg-slate-950/80 text-white font-heading font-bold text-xs font-mono"
              />
            </div>

            <div>
              <label className="text-[11px] font-semibold text-slate-600 dark:text-slate-400 block mb-1">
                Environment
              </label>
              <input
                type="text"
                value={environment}
                onChange={(e) => setEnvironment(e.target.value)}
                required
                className="w-full px-3 py-2 rounded-lg border border-white/15 dark:border-slate-700 bg-slate-950/80 text-white font-heading font-bold text-xs"
              />
            </div>

            <div>
              <label className="text-[11px] font-semibold text-slate-600 dark:text-slate-400 block mb-1">
                Repository (Canonical URI)
              </label>
              <input
                type="text"
                value={repository}
                onChange={(e) => setRepository(e.target.value)}
                required
                className="w-full px-3 py-2 rounded-lg border border-white/15 dark:border-slate-700 bg-slate-950/80 text-white font-heading font-bold text-xs font-mono"
              />
            </div>

            <div>
              <label className="text-[11px] font-semibold text-slate-600 dark:text-slate-400 block mb-1">
                Deployment Tag
              </label>
              <input
                type="text"
                value={deployment}
                onChange={(e) => setDeployment(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-white/15 dark:border-slate-700 bg-slate-950/80 text-white font-heading font-bold text-xs font-mono"
              />
            </div>

            <div>
              <label className="text-[11px] font-semibold text-slate-600 dark:text-slate-400 block mb-1">
                Cloud Provider
              </label>
              <input
                type="text"
                value={cloudProvider}
                onChange={(e) => setCloudProvider(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-white/15 dark:border-slate-700 bg-slate-950/80 text-white font-heading font-bold text-xs"
              />
            </div>

            <div>
              <label className="text-[11px] font-semibold text-slate-600 dark:text-slate-400 block mb-1">
                Incident Time
              </label>
              <input
                type="text"
                value={incidentTime}
                onChange={(e) => setIncidentTime(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-white/15 dark:border-slate-700 bg-slate-950/80 text-white font-heading font-bold text-xs font-mono"
              />
            </div>
          </div>
        </div>

        {/* Evidence Sources Checkboxes (Section 4) */}
        <div className="p-5 rounded-xl border border-white/10 bg-slate-900/80 shadow-2xs space-y-3">
          <div>
            <div className="text-xs font-bold uppercase tracking-wider text-slate-300 dark:text-slate-300">
              Evidence Sources To Ingest
            </div>
            <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
              Select available data sources for multi-modal evidence correlation.
            </p>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-1">
            {Object.entries(sources).map(([name, isChecked]) => (
              <button
                key={name}
                type="button"
                onClick={() => toggleSource(name)}
                className={`p-3 rounded-lg border text-left flex items-center justify-between transition-all ${
                  isChecked
                    ? 'bg-indigo-500/100/10/50 border-indigo-300 dark:border-indigo-800 text-indigo-950 dark:text-indigo-200 font-semibold'
                    : 'bg-slate-950/80/40 border-white/10 text-slate-500 dark:text-slate-400'
                }`}
              >
                <span className="text-xs">{name}</span>
                {isChecked ? (
                  <CheckSquare size={16} className="text-indigo-600 dark:text-indigo-400 shrink-0" />
                ) : (
                  <Square size={16} className="text-slate-300 dark:text-slate-600 shrink-0" />
                )}
              </button>
            ))}
          </div>
        </div>

        {/* Primary Action Button */}
        <div className="flex justify-end pt-2">
          <button
            type="submit"
            className="flex items-center gap-2 px-6 py-3 rounded-xl bg-slate-900 dark:bg-slate-900/80 text-white dark:text-white font-bold text-xs tracking-tight shadow-md hover:bg-slate-800 dark:hover:bg-slate-800/70 transition-all"
          >
            <Play size={15} />
            <span>Start Real Investigation</span>
          </button>
        </div>
      </form>
    </div>
  );
}
