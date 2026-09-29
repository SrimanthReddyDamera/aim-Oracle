import React, { useState, useEffect } from 'react';
import { 
  Activity, 
  Search, 
  FolderGit2, 
  Wrench, 
  Cpu, 
  ShieldCheck, 
  Settings, 
  ChevronLeft, 
  ChevronRight, 
  Terminal,
  Radio,
  FileCheck,
  Layers
} from 'lucide-react';
import { oracleApi, ApiMode } from '../../lib/api';
import { audioFx } from '../../lib/audio';

interface SidebarProps {
  currentTab: string;
  onNavigate: (tab: string) => void;
  collapsed: boolean;
  onToggleCollapse: () => void;
  activeIncidentId: string;
}

export function Sidebar({ 
  currentTab, 
  onNavigate, 
  collapsed, 
  onToggleCollapse, 
  activeIncidentId 
}: SidebarProps) {
  const [healthStatus, setHealthStatus] = useState<'OPERATIONAL' | 'DEGRADED'>('OPERATIONAL');
  const [latencyMs, setLatencyMs] = useState(12);

  useEffect(() => {
    const check = () => {
      oracleApi.getHealth().then((res) => {
        setHealthStatus(res.status);
        setLatencyMs(res.latencyMs);
      }).catch(() => {
        setHealthStatus('DEGRADED');
      });
    };
    check();
    const interval = setInterval(check, 10000);
    return () => clearInterval(interval);
  }, []);

  const navGroups = [
    {
      group: null,
      items: [
        { id: 'overview', label: 'Overview', icon: Activity },
      ],
    },
    {
      group: 'Investigate',
      items: [
        { id: 'investigate', label: 'Investigate', icon: Terminal },
        { id: 'workspace', label: 'Investigations', icon: Search, badge: activeIncidentId ? 'ACTIVE' : undefined },
        { id: 'evidence', label: 'Evidence', icon: FolderGit2 },
      ],
    },
    {
      group: 'Resolutions',
      items: [
        { id: 'agent-tasks', label: 'Agent Tasks', icon: Cpu },
      ],
    },
    {
      group: 'Sandbox',
      items: [
        { id: 'verification', label: 'Verification', icon: ShieldCheck, badge: 'GATE' },
      ],
    },
    {
      group: 'Security',
      items: [
        { id: 'security', label: 'Audit', icon: FileCheck },
        { id: 'settings', label: 'Settings', icon: Settings },
      ],
    },
  ];

  return (
    <aside
      className={`border-r border-cyan-500/20 bg-[#020617] flex flex-col justify-between transition-all duration-300 z-10 font-mono select-none ${
        collapsed ? 'w-16' : 'w-60'
      }`}
    >
      <div>
        {/* Brand Banner */}
        <div className="h-14 flex items-center justify-between px-4 border-b border-cyan-500/20 bg-slate-950/60">
          {!collapsed && (
            <div className="flex items-center gap-2.5">
              <div className="w-7 h-7 rounded bg-cyan-500/10 border border-cyan-400 flex items-center justify-center text-cyan-300 font-bold text-xs shadow-[0_0_12px_rgba(0,246,255,0.3)]">
                Ω
              </div>
              <div>
                <div className="font-bold text-white tracking-widest text-xs">ORACLE</div>
                <div className="text-[9px] text-cyan-400/70 tracking-wider">CONTROL PLANE</div>
              </div>
            </div>
          )}
          {collapsed && (
            <div className="mx-auto w-7 h-7 rounded bg-cyan-500/10 border border-cyan-400 flex items-center justify-center text-cyan-300 font-bold text-xs">
              Ω
            </div>
          )}

          <button
            onClick={() => {
              audioFx.click();
              onToggleCollapse();
            }}
            className="text-slate-500 hover:text-cyan-400 p-1 transition-colors"
            title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
          </button>
        </div>

        {/* Navigation Items */}
        <div className="py-4 space-y-5 px-2">
          {navGroups.map((grp, gIdx) => (
            <div key={gIdx} className="space-y-1">
              {!collapsed && grp.group && (
                <div className="px-3 text-[10px] font-bold text-slate-500 uppercase tracking-widest">
                  {grp.group}
                </div>
              )}
              {grp.items.map((item) => {
                const Icon = item.icon;
                const isActive = currentTab === item.id;
                return (
                  <button
                    key={item.id}
                    onClick={() => {
                      audioFx.click();
                      onNavigate(item.id);
                    }}
                    className={`w-full flex items-center gap-3 px-3 py-2 rounded text-xs transition-all ${
                      isActive
                        ? 'bg-cyan-500/15 text-cyan-200 border border-cyan-500/40 shadow-[0_0_15px_rgba(0,246,255,0.15)] font-bold'
                        : 'text-slate-400 hover:text-white hover:bg-white/5 border border-transparent'
                    }`}
                  >
                    <Icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                    {!collapsed && <span className="truncate">{item.label}</span>}
                    {!collapsed && item.badge && (
                      <span className="ml-auto text-[9px] px-1.5 py-0.2 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold tracking-wider">
                        {item.badge}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          ))}
        </div>
      </div>

      {/* Bottom Mission-Control Telemetry Box */}
      <div className="p-3 border-t border-cyan-500/20 bg-slate-950/80 text-[10px] text-slate-400">
        {!collapsed ? (
          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="flex items-center gap-1.5 text-emerald-400 font-bold">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping" />
                {healthStatus}
              </span>
              <span className="text-cyan-300 font-mono">{latencyMs}ms</span>
            </div>
            <div className="text-[9px] text-slate-500">eBPF KERNEL ENFORCED</div>
          </div>
        ) : (
          <div className="w-2 h-2 mx-auto rounded-full bg-emerald-400 animate-ping" />
        )}
      </div>
    </aside>
  );
}
