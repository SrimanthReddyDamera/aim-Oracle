import React, { useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  ArrowRight, 
  Terminal, 
  ShieldCheck, 
  Sparkles, 
  Github, 
  Search, 
  CheckCircle2, 
  AlertTriangle, 
  RefreshCw, 
  QrCode, 
  ExternalLink,
  ChevronRight,
  FolderGit2,
  Cpu,
  Layers,
  FileCode2,
  Lock,
  Play,
  Activity,
  FileText,
  DollarSign,
  HelpCircle,
  Calendar,
  BarChart3,
  User,
  Settings,
  Sliders,
  Send,
  Paperclip,
  Check,
  ChevronDown
} from 'lucide-react';
import { Button } from '../ui/button';
import { Badge } from '../ui/badge';
import { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter } from '../ui/card';
import { Input } from '../ui/input';
import { Switch } from '../ui/switch';
import { Separator } from '../ui/separator';

interface LandingPageViewProps {
  onEnterConsole: (tab?: string) => void;
  onExploreIncident?: (incidentId: string) => void;
}

export function LandingPageView({ onEnterConsole, onExploreIncident }: LandingPageViewProps) {
  // Interactive state in the showcase cards
  const [toggleActive, setToggleActive] = useState(true);
  const [goalName, setGoalName] = useState('Payment API Zero-Regression');
  const [targetAmount, setTargetAmount] = useState('18.42s');
  const [targetDate, setTargetDate] = useState('May 2026');
  const [chatPrompt, setChatPrompt] = useState('');
  const [chatResponses, setChatResponses] = useState<string[]>([
    'ORACLE isolated root cause for INC-1042 to commit 8f2a41d with 94.2% confidence. Sandbox replay verified in 18.42s.'
  ]);
  const [thresholdVal, setThresholdVal] = useState(99.4);
  const [demoRunning, setDemoRunning] = useState(false);
  const [demoStep, setDemoStep] = useState(0);

  const runLiveDemo = () => {
    setDemoRunning(true);
    setDemoStep(1);
    setTimeout(() => setDemoStep(2), 600);
    setTimeout(() => setDemoStep(3), 1200);
    setTimeout(() => setDemoStep(4), 1800);
    setTimeout(() => {
      setDemoRunning(false);
      onEnterConsole('workspace');
    }, 2400);
  };

  const handleSendChat = (e: React.FormEvent) => {
    e.preventDefault();
    if (!chatPrompt.trim()) return;
    const userMsg = chatPrompt;
    setChatPrompt('');
    setChatResponses(prev => [...prev, `Synthesized AST diff for ${userMsg}. Sandbox test suite passing with 0 regressions.`]);
  };

  return (
    <div className="min-h-screen bg-neutral-50/60 dark:bg-neutral-950 text-neutral-900 dark:text-neutral-50 dot-pattern font-sans antialiased selection:bg-neutral-900 selection:text-white dark:selection:bg-white dark:selection:text-neutral-950">
      
      {/* ── Top Header Navigation (Identical to shadcn.com header) ── */}
      <header className="sticky top-0 z-50 w-full border-b border-neutral-200/80 bg-white/85 backdrop-blur-md dark:border-neutral-800 dark:bg-neutral-950/85">
        <div className="max-w-7xl mx-auto flex h-14 items-center justify-between px-4 sm:px-8">
          {/* Left Brand & Nav links */}
          <div className="flex items-center gap-6">
            <button 
              onClick={() => onEnterConsole('landing')}
              className="flex items-center gap-2 font-bold text-sm tracking-tight text-neutral-900 dark:text-white hover:opacity-80 transition-opacity"
            >
              <div className="w-5 h-5 rounded bg-neutral-900 dark:bg-white flex items-center justify-center text-white dark:text-neutral-900 text-xs font-black">
                Ω
              </div>
              <span className="font-heading font-extrabold text-base tracking-tight">ORACLE</span>
            </button>

            <nav className="hidden md:flex items-center gap-5 text-xs font-medium text-neutral-600 dark:text-neutral-400">
              <button onClick={() => onEnterConsole('landing')} className="text-neutral-950 dark:text-white font-semibold">Home</button>
              <button onClick={() => onEnterConsole('overview')} className="hover:text-neutral-900 dark:hover:text-white transition-colors">Overview</button>
              <button onClick={() => onEnterConsole('workspace')} className="hover:text-neutral-900 dark:hover:text-white transition-colors">Investigations</button>
              <button onClick={() => onEnterConsole('evidence')} className="hover:text-neutral-900 dark:hover:text-white transition-colors">Evidence</button>
              <button onClick={() => onEnterConsole('resolutions')} className="hover:text-neutral-900 dark:hover:text-white transition-colors">Resolutions</button>
              <button onClick={() => onEnterConsole('verification')} className="hover:text-neutral-900 dark:hover:text-white transition-colors">Sandbox Gate</button>
            </nav>
          </div>

          {/* Right Action buttons */}
          <div className="flex items-center gap-3">
            <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-lg border border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-neutral-900 text-xs text-neutral-500">
              <Search size={13} />
              <span>Search incidents, logs, diffs...</span>
              <kbd className="font-mono text-[10px] bg-neutral-200 dark:bg-neutral-800 px-1.5 py-0.5 rounded text-neutral-700 dark:text-neutral-300">⌘K</kbd>
            </div>

            <a
              href="https://github.com"
              target="_blank"
              rel="noreferrer"
              className="flex items-center gap-1.5 text-xs text-neutral-600 dark:text-neutral-400 hover:text-neutral-900 dark:hover:text-white transition-colors px-2 py-1"
            >
              <Github size={15} />
              <span className="font-medium hidden sm:inline">125k</span>
            </a>

            <Button 
              onClick={() => onEnterConsole('workspace')}
              className="rounded-lg shadow-sm font-semibold text-xs"
              size="sm"
            >
              <span>+ Launch Console</span>
            </Button>
          </div>
        </div>
      </header>

      {/* ── Hero Section with Extraordinary Motion ── */}
      <section className="relative pt-16 pb-12 px-4 sm:px-8 max-w-5xl mx-auto text-center">
        <motion.div
          initial={{ opacity: 0, y: 15 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4 }}
          className="inline-flex items-center gap-2 px-3.5 py-1 rounded-full border border-neutral-200 bg-white dark:border-neutral-800 dark:bg-neutral-900 text-xs font-medium text-neutral-800 dark:text-neutral-200 mb-6 shadow-2xs hover:border-neutral-300 transition-colors"
        >
          <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
          <span className="font-semibold">ORACLE 2.0</span>
          <span className="text-neutral-400">/</span>
          <span>Never confuse a proposed fix with a verified fix.</span>
          <ArrowRight size={13} className="text-neutral-400" />
        </motion.div>

        <motion.h1 
          initial={{ opacity: 0, y: 15 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.05 }}
          className="text-4xl sm:text-6xl font-extrabold tracking-tight font-heading text-neutral-950 dark:text-white leading-[1.08] max-w-4xl mx-auto"
        >
          Build software that <span className="underline decoration-neutral-300 dark:decoration-neutral-700 underline-offset-8">repairs itself</span>.
        </motion.h1>

        <motion.p 
          initial={{ opacity: 0, y: 15 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.1 }}
          className="mt-6 text-base sm:text-lg text-neutral-600 dark:text-neutral-400 max-w-2xl mx-auto leading-relaxed"
        >
          The autonomous incident intelligence control plane. Ingests production alerts, correlates git commits and traces, synthesizes AST patches, and proves zero regressions in an isolated Docker sandbox.
        </motion.p>

        {/* Hero CTA Buttons */}
        <motion.div 
          initial={{ opacity: 0, y: 15 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.15 }}
          className="mt-8 flex flex-wrap items-center justify-center gap-3.5"
        >
          <Button 
            onClick={() => onEnterConsole('workspace')}
            size="lg"
            className="rounded-xl px-6 py-2.5 font-bold text-sm shadow-md"
          >
            <span>Launch Command Console</span>
            <ArrowRight size={16} />
          </Button>

          <Button 
            onClick={runLiveDemo}
            variant="outline"
            size="lg"
            className="rounded-xl px-6 py-2.5 font-semibold text-sm"
          >
            {demoRunning ? (
              <>
                <RefreshCw size={15} className="animate-spin text-neutral-900 dark:text-white" />
                <span>Simulating Replay (Step {demoStep}/4)...</span>
              </>
            ) : (
              <>
                <Play size={14} className="fill-current" />
                <span>Live Interactive Demo</span>
              </>
            )}
          </Button>
        </motion.div>
      </section>

      {/* ── THE LIVING SHADCN BENTO SHOWCASE (Exactly matching Image 1) ── */}
      <section className="max-w-7xl mx-auto px-4 sm:px-8 pb-24">
        <motion.div 
          initial={{ opacity: 0, y: 25 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.2 }}
          className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-12 gap-5"
        >
          
          {/* ── CARD 1: Interactive Component Primitives (Image 1, Top Left) ── */}
          <div className="lg:col-span-3 bento-card p-6 flex flex-col justify-between space-y-5">
            <div className="space-y-4">
              {/* Button Group */}
              <div className="flex items-center gap-2 flex-wrap">
                <Button size="sm" className="rounded-full px-4 font-semibold">
                  <span>Button</span>
                  <ArrowRight size={13} />
                </Button>
                <Button size="sm" variant="secondary" className="rounded-full px-3.5">
                  Secondary
                </Button>
                <Button size="sm" variant="outline" className="rounded-full px-3.5">
                  Outline
                </Button>
              </div>

              {/* Inputs */}
              <div className="space-y-2">
                <div className="relative">
                  <Input placeholder="Name" className="rounded-xl bg-neutral-50/80 dark:bg-neutral-900 pr-8" />
                  <Search size={14} className="absolute right-3 top-2.5 text-neutral-400" />
                </div>
                <Input placeholder="Message" className="rounded-xl bg-neutral-50/80 dark:bg-neutral-900" />
              </div>

              {/* Badges & Switch */}
              <div className="flex items-center justify-between pt-1">
                <div className="flex items-center gap-2">
                  <Badge variant="default" className="rounded-full px-3">Badge</Badge>
                  <Badge variant="secondary" className="rounded-full px-3">Secondary</Badge>
                </div>
                <div className="flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded-full bg-neutral-900 dark:bg-white" />
                  <Switch checked={toggleActive} onCheckedChange={setToggleActive} />
                </div>
              </div>

              {/* Action Buttons Row */}
              <div className="flex items-center gap-2 pt-1">
                <Button size="sm" variant="outline" className="rounded-xl text-xs flex-1">
                  Alert Dialog
                </Button>
                <Button size="sm" variant="outline" className="rounded-xl text-xs flex-1 flex items-center justify-between">
                  <span>Button Group</span>
                  <ChevronDown size={13} />
                </Button>
              </div>
            </div>

            {/* Micro Navigation rail matching Image 1 bottom-left */}
            <div className="pt-4 border-t border-neutral-100 dark:border-neutral-800 space-y-3">
              <div>
                <span className="text-[11px] font-semibold text-neutral-400 uppercase tracking-wider block mb-1.5">Planning</span>
                <div className="grid grid-cols-2 gap-1 text-xs text-neutral-600 dark:text-neutral-400">
                  <span className="hover:text-neutral-950 dark:hover:text-white cursor-pointer py-0.5">📄 Documents</span>
                  <span className="hover:text-neutral-950 dark:hover:text-white cursor-pointer py-0.5">💰 Budget</span>
                  <span className="hover:text-neutral-950 dark:hover:text-white cursor-pointer py-0.5">📊 Reports</span>
                  <span className="hover:text-neutral-950 dark:hover:text-white cursor-pointer py-0.5">🎯 Goals</span>
                </div>
              </div>

              <div>
                <span className="text-[11px] font-semibold text-neutral-400 uppercase tracking-wider block mb-1.5">Support</span>
                <div className="grid grid-cols-2 gap-1 text-xs text-neutral-600 dark:text-neutral-400">
                  <span className="hover:text-neutral-950 dark:hover:text-white cursor-pointer py-0.5">❓ Help Center</span>
                  <span className="hover:text-neutral-950 dark:hover:text-white cursor-pointer py-0.5">📚 Docs</span>
                </div>
              </div>
            </div>
          </div>

          {/* ── CARD 2: Contribution / Incident History Bar Chart (Image 1, Center Left) ── */}
          <div className="lg:col-span-3 bento-card p-6 flex flex-col justify-between space-y-5">
            <div>
              <h3 className="font-heading font-bold text-base text-neutral-950 dark:text-white">
                Contribution History
              </h3>
              <p className="text-xs text-neutral-500 dark:text-neutral-400 mt-0.5">
                Last 6 months of activity
              </p>

              {/* 5 Vertical Rounded Bars matching Image 1 */}
              <div className="flex items-end justify-between gap-3 h-44 pt-6 pb-2">
                {[
                  { month: 'Dec', height: '65%' },
                  { month: 'Jan', height: '42%' },
                  { month: 'Feb', height: '88%' },
                  { month: 'Mar', height: '95%' },
                  { month: 'Apr', height: '70%' },
                ].map((item, idx) => (
                  <div key={item.month} className="flex-1 flex flex-col items-center gap-2 h-full justify-end">
                    <motion.div 
                      initial={{ height: 0 }}
                      animate={{ height: item.height }}
                      transition={{ duration: 0.6, delay: idx * 0.1 }}
                      className="w-full rounded-xl bg-neutral-900 dark:bg-neutral-100 hover:opacity-85 transition-opacity cursor-pointer"
                    />
                    <span className="text-[11px] font-medium text-neutral-500 dark:text-neutral-400">{item.month}</span>
                  </div>
                ))}
              </div>

              {/* 2 Sub-metrics */}
              <div className="grid grid-cols-2 gap-3 mt-4 pt-4 border-t border-neutral-100 dark:border-neutral-800">
                <div className="p-3 rounded-xl bg-neutral-50 dark:bg-neutral-900">
                  <span className="text-[10px] uppercase font-bold text-neutral-400 tracking-wider block">Upcoming</span>
                  <span className="text-xs font-bold text-neutral-900 dark:text-white block mt-0.5">May 2026</span>
                  <span className="text-[10px] text-neutral-500">Scheduled</span>
                </div>
                <div className="p-3 rounded-xl bg-neutral-50 dark:bg-neutral-900">
                  <span className="text-[10px] uppercase font-bold text-neutral-400 tracking-wider block">Savings Plan</span>
                  <span className="text-xs font-bold text-neutral-900 dark:text-white block mt-0.5">Accelerated</span>
                  <span className="text-[10px] text-neutral-500">Recurring</span>
                </div>
              </div>
            </div>

            <Button 
              onClick={() => onEnterConsole('workspace')}
              className="w-full rounded-xl font-bold text-xs"
            >
              View Full Report
            </Button>
          </div>

          {/* ── CARD 3: Set a New Milestone / Target Form (Image 1, Center Right) ── */}
          <div className="lg:col-span-3 bento-card p-6 flex flex-col justify-between space-y-4">
            <div className="space-y-4">
              <div>
                <h3 className="font-heading font-bold text-base text-neutral-950 dark:text-white">
                  Set a new milestone
                </h3>
                <p className="text-xs text-neutral-500 dark:text-neutral-400 mt-1 leading-snug">
                  Define your financial target and we'll help you pace your savings.
                </p>
              </div>

              <div className="space-y-3">
                <div className="space-y-1.5">
                  <label className="text-xs font-semibold text-neutral-700 dark:text-neutral-300">Goal Name</label>
                  <Input 
                    value={goalName}
                    onChange={(e) => setGoalName(e.target.value)}
                    placeholder="e.g. New Car, Home Downpayment" 
                    className="rounded-xl bg-neutral-50/80 dark:bg-neutral-900"
                  />
                </div>

                <div className="grid grid-cols-2 gap-2.5">
                  <div className="space-y-1.5">
                    <label className="text-xs font-semibold text-neutral-700 dark:text-neutral-300">Target Amount</label>
                    <Input 
                      value={targetAmount}
                      onChange={(e) => setTargetAmount(e.target.value)}
                      placeholder="$15,000" 
                      className="rounded-xl bg-neutral-50/80 dark:bg-neutral-900"
                    />
                  </div>
                  <div className="space-y-1.5">
                    <label className="text-xs font-semibold text-neutral-700 dark:text-neutral-300">Target Date</label>
                    <Input 
                      value={targetDate}
                      onChange={(e) => setTargetDate(e.target.value)}
                      placeholder="Dec 2026" 
                      className="rounded-xl bg-neutral-50/80 dark:bg-neutral-900"
                    />
                  </div>
                </div>
              </div>

              <div className="space-y-2 pt-2">
                <Button 
                  onClick={() => alert(`Milestone '${goalName}' committed to ORACLE SLA governance!`)}
                  className="w-full rounded-xl font-bold text-xs"
                >
                  Create Goal
                </Button>
                <Button 
                  variant="outline" 
                  onClick={() => setGoalName('Payment API Zero-Regression')}
                  className="w-full rounded-xl text-xs font-medium"
                >
                  Cancel
                </Button>
              </div>
            </div>

            {/* Payout Threshold Micro-Card (Matching Image 1 bottom-center) */}
            <div className="pt-4 border-t border-neutral-100 dark:border-neutral-800 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-neutral-900 dark:text-white">Payout Threshold</span>
                <span className="text-xs text-neutral-400">✕</span>
              </div>
              <p className="text-[11px] text-neutral-500 leading-tight">
                Set the minimum balance required before a payout is triggered.
              </p>
              <div className="p-2 rounded-lg bg-neutral-100 dark:bg-neutral-900 text-xs font-medium flex items-center justify-between">
                <span>USD — United States Dollar</span>
                <ChevronDown size={13} className="text-neutral-400" />
              </div>
            </div>
          </div>

          {/* ── CARD 4: Scan to Connect QR + Chat Assistant (Image 1, Right Column) ── */}
          <div className="lg:col-span-3 space-y-5">
            {/* QR Card */}
            <div className="bento-card p-6 flex flex-col items-center text-center space-y-3">
              {/* Minimal SVG QR Code */}
              <div className="w-28 h-28 p-2 rounded-xl bg-white border border-neutral-200 dark:border-neutral-800 flex items-center justify-center shadow-xs">
                <svg viewBox="0 0 100 100" className="w-full h-full text-neutral-950">
                  <path fill="currentColor" d="M10,10 h30 v30 h-30 z M15,15 v20 h20 v-20 z M20,20 h10 v10 h-10 z" />
                  <path fill="currentColor" d="M60,10 h30 v30 h-30 z M65,15 v20 h20 v-20 z M70,20 h10 v10 h-10 z" />
                  <path fill="currentColor" d="M10,60 h30 v30 h-30 z M15,65 v20 h20 v-20 z M20,70 h10 v10 h-10 z" />
                  <path fill="currentColor" d="M45,15 h10 v10 h-10 z M45,35 h10 v20 h-10 z M65,45 h10 v10 h-10 z M75,55 h15 v10 h-15 z M55,65 h10 v25 h-10 z M75,75 h15 v15 h-15 z M45,75 h8 v10 h-8 z" />
                </svg>
              </div>

              <div>
                <h4 className="font-heading font-bold text-sm text-neutral-950 dark:text-white">
                  Scan to connect your mobile device
                </h4>
                <p className="text-[11px] text-neutral-500 dark:text-neutral-400 mt-1">
                  Open the Ledger mobile app and scan this code to link your device.
                </p>
              </div>
            </div>

            {/* New Chat Copilot Card (Image 1, bottom right) */}
            <div className="bento-card p-5 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="font-heading font-bold text-xs text-neutral-950 dark:text-white">New Chat</span>
                </div>
                <RefreshCw 
                  size={13} 
                  className="text-neutral-400 hover:text-neutral-950 dark:hover:text-white cursor-pointer transition-colors"
                  onClick={() => setChatResponses(['How can I assist your incident investigation?'])}
                />
              </div>
              <p className="text-xs text-neutral-500">How can I help you today?</p>

              <div className="p-3 rounded-xl bg-neutral-50 dark:bg-neutral-900 border border-neutral-100 dark:border-neutral-800 text-xs text-neutral-700 dark:text-neutral-300 space-y-2 max-h-24 overflow-y-auto">
                <div className="font-semibold text-neutral-900 dark:text-white flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                  Morning, engineer!
                </div>
                {chatResponses.map((r, i) => (
                  <p key={i} className="text-[11px] leading-tight text-neutral-600 dark:text-neutral-400">{r}</p>
                ))}
              </div>

              <form onSubmit={handleSendChat} className="relative">
                <Input 
                  value={chatPrompt}
                  onChange={(e) => setChatPrompt(e.target.value)}
                  placeholder="Ask about commit 8f2a41d..."
                  className="pr-8 rounded-xl text-xs bg-neutral-50/80 dark:bg-neutral-900"
                />
                <button type="submit" className="absolute right-2.5 top-2.5 text-neutral-400 hover:text-neutral-950 dark:hover:text-white cursor-pointer">
                  <Send size={13} />
                </button>
              </form>
            </div>
          </div>

        </motion.div>
      </section>

      {/* ── SECTION: HOW ORACLE RESOLVES PRODUCTION OUTAGES (CSI Pipeline) ── */}
      <section className="border-t border-neutral-200/80 dark:border-neutral-800 bg-white dark:bg-neutral-950 py-20 px-4 sm:px-8">
        <div className="max-w-6xl mx-auto">
          <div className="text-center max-w-2xl mx-auto mb-14">
            <Badge variant="outline" className="rounded-full px-3 py-1 text-xs font-semibold mb-3">
              The 5-Stage Zero-Trust Engine
            </Badge>
            <h2 className="text-3xl sm:text-4xl font-extrabold tracking-tight font-heading text-neutral-950 dark:text-white">
              From raw 500 error to signed verified PR.
            </h2>
            <p className="mt-3 text-sm text-neutral-600 dark:text-neutral-400">
              ORACLE eliminates guesswork by combining temporal git correlation with isolated sandbox replay verification.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <Card className="rounded-2xl border-neutral-200 dark:border-neutral-800">
              <CardHeader>
                <div className="w-10 h-10 rounded-xl bg-neutral-100 dark:bg-neutral-900 flex items-center justify-center text-neutral-900 dark:text-white font-bold mb-2">
                  01
                </div>
                <CardTitle>Multi-Modal Forensic Ingestion</CardTitle>
                <CardDescription>
                  Scrapes container logs, Sentry stack traces, database slow query logs, and git diffs from the last 24 hours into a unified timeline.
                </CardDescription>
              </CardHeader>
              <CardContent className="text-xs text-neutral-500 font-mono">
                → 12,400 logs correlated in 0.4s
              </CardContent>
            </Card>

            <Card className="rounded-2xl border-neutral-200 dark:border-neutral-800">
              <CardHeader>
                <div className="w-10 h-10 rounded-xl bg-neutral-100 dark:bg-neutral-900 flex items-center justify-center text-neutral-900 dark:text-white font-bold mb-2">
                  02
                </div>
                <CardTitle>Autonomous Patch Synthesis</CardTitle>
                <CardDescription>
                  Generates a minimal, surgical code diff correcting the fault (adding defensive null-checks and token fallbacks) without hallucination.
                </CardDescription>
              </CardHeader>
              <CardContent className="text-xs text-neutral-500 font-mono">
                → 14-line AST clean diff verified
              </CardContent>
            </Card>

            <Card className="rounded-2xl border-neutral-200 dark:border-neutral-800">
              <CardHeader>
                <div className="w-10 h-10 rounded-xl bg-neutral-100 dark:bg-neutral-900 flex items-center justify-center text-neutral-900 dark:text-white font-bold mb-2">
                  03
                </div>
                <CardTitle>Sandbox Replay Proof Gate</CardTitle>
                <CardDescription>
                  Never trust code without execution. Replays 500+ production requests in an isolated container to establish the 4 Pillars of Proof.
                </CardDescription>
              </CardHeader>
              <CardContent className="text-xs text-neutral-500 font-mono">
                → 18.42s execution, 0 regressions
              </CardContent>
            </Card>
          </div>

          {/* Bottom Banner */}
          <div className="mt-12 p-8 rounded-2xl bg-neutral-900 dark:bg-white text-white dark:text-neutral-950 flex flex-col md:flex-row items-center justify-between gap-6 shadow-xl">
            <div>
              <h3 className="text-xl font-bold font-heading">
                Ready to explore the active investigation workspace?
              </h3>
              <p className="text-sm opacity-80 mt-1">
                Explore canonical incident INC-1042 (Payment API 500 Outage) with live telemetry.
              </p>
            </div>
            <Button 
              onClick={() => onEnterConsole('workspace')}
              size="lg"
              className="rounded-xl bg-white text-neutral-950 hover:bg-neutral-200 dark:bg-neutral-950 dark:text-white dark:hover:bg-neutral-800 font-bold shrink-0"
            >
              <span>Open INC-1042 Workspace</span>
              <ArrowRight size={16} />
            </Button>
          </div>
        </div>
      </section>

      {/* ── Footer ── */}
      <footer className="border-t border-neutral-200 dark:border-neutral-800 py-8 px-4 sm:px-8 text-xs text-neutral-500 dark:text-neutral-400">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <span className="font-bold text-neutral-900 dark:text-white font-heading">ORACLE</span>
            <span>— Autonomous Incident Intelligence & Resolution Platform.</span>
          </div>
          <div className="flex items-center gap-6">
            <button onClick={() => onEnterConsole('overview')} className="hover:underline">System Overview</button>
            <button onClick={() => onEnterConsole('workspace')} className="hover:underline">Workspace</button>
            <button onClick={() => onEnterConsole('verification')} className="hover:underline">Sandbox</button>
            <button onClick={() => onEnterConsole('security')} className="hover:underline">Security</button>
          </div>
        </div>
      </footer>
    </div>
  );
}
