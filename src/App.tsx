import { useState, useEffect, useMemo } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { 
  Activity, 
  Terminal, 
  Trash2, 
  RefreshCw, 
  Search, 
  Folder, 
  Cpu, 
  History, 
  X,
  Eye, 
  AlertTriangle,
  Info,
  Server,
  Database,
  Globe,
  Layers,
  Shield,
  CheckCircle,
  Menu
} from 'lucide-react';
import { inspectPort, PortContext } from './aiService';

interface PortInfo {
  port: number;
  pid: number;
  process_name: string;
  protocol: string;
  user: string;
  memory?: string;
}

interface DiagnosticLog {
  id: string;
  timestamp: string;
  port: number;
  processName: string;
  pid: number;
  protocol: string;
  analysis: string;
  followUps: Array<{ role: 'user' | 'assistant'; content: string }>;
}

const LOCAL_SERVER = 'http://127.0.0.1:12200';

async function apiInvoke<T>(cmd: string, args?: any): Promise<T> {
  const isLocalBrowserOrExtension = typeof window !== 'undefined' && (
    window.location.protocol === 'chrome-extension:' ||
    window.location.protocol === 'http:' ||
    window.location.protocol === 'https:'
  );

  if (!isLocalBrowserOrExtension) {
    return await invoke<T>(cmd, args);
  }

  let path = '';
  let method = 'GET';
  let body: any = null;

  if (cmd === 'get_active_ports') {
    path = '/ports';
    method = 'GET';
  } else if (cmd === 'kill_process') {
    path = '/kill';
    method = 'POST';
    body = JSON.stringify({ pid: args.pid });
  } else if (cmd === 'analyze_port_local') {
    path = '/analyze';
    method = 'POST';
    body = JSON.stringify({
      port: args.port,
      processName: args.processName,
      isSystem: args.isSystem
    });
  }

  try {
    const response = await fetch(`${LOCAL_SERVER}${path}`, {
      method,
      headers: {
        'Content-Type': 'application/json',
      },
      body,
    });

    if (!response.ok) {
      const errText = await response.text();
      throw new Error(errText || `HTTP error ${response.status}`);
    }

    return await response.json() as T;
  } catch (e) {
    if (window.location.protocol === 'http:' || window.location.protocol === 'https:') {
      console.warn('Local HTTP server unreachable, falling back to browser mocks...', e);
      return await invoke<T>(cmd, args);
    }
    throw e;
  }
}

export default function App() {
  // State
  const [ports, setPorts] = useState<PortInfo[]>([]);
  const [portAnalyses, setPortAnalyses] = useState<Record<string, { category: string; importance: string; safety: string; reasoning: string }>>({});
  const [isLoading, setIsLoading] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [activeTab, setActiveTab] = useState<'all' | 'projects' | 'logs'>('all');
  const [aiEnabled, setAiEnabled] = useState(true);
  const [serverUnreachable, setServerUnreachable] = useState(false);
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false);

  // Diagnostic Drawer State
  const [selectedPort, setSelectedPort] = useState<PortInfo | null>(null);
  const [aiDrawerOpen, setAiDrawerOpen] = useState(false);
  const [selectedAnalysis, setSelectedAnalysis] = useState<any>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);

  // Kill Process State
  const [portToKill, setPortToKill] = useState<PortInfo | null>(null);
  const [killConfirmInput, setKillConfirmInput] = useState('');
  const [isKilling, setIsKilling] = useState(false);
  const [killError, setKillError] = useState<string | null>(null);

  // Success Toast State
  const [successToast, setSuccessToast] = useState<{ show: boolean; message: string; subMessage?: string } | null>(null);

  // Diagnostics Logs
  const [diagnosticLogs, setDiagnosticLogs] = useState<DiagnosticLog[]>(() => {
    const saved = localStorage.getItem('portintel_diagnostic_logs');
    return saved ? JSON.parse(saved) : [];
  });

  // OS Detection
  const os = useMemo<'macos' | 'windows' | 'linux'>(() => {
    const ua = navigator.userAgent.toLowerCase();
    if (ua.includes('mac')) return 'macos';
    if (ua.includes('win')) return 'windows';
    return 'linux';
  }, []);

  // Automatically clear toast notification after timeout
  useEffect(() => {
    if (successToast && successToast.show) {
      const timer = setTimeout(() => {
        setSuccessToast(null);
      }, 4000);
      return () => clearTimeout(timer);
    }
  }, [successToast]);

  // Run local ONNX ML analysis for all ports automatically
  const analyzePorts = async (portList: PortInfo[]) => {
    const newAnalyses = { ...portAnalyses };
    let changed = false;
    
    await Promise.all(
      portList.map(async (p) => {
        const key = `${p.port}-${p.pid}`;
        if (!newAnalyses[key]) {
          try {
            const processLower = p.process_name?.toLowerCase() || '';
            const isSystem = p.user?.toLowerCase().includes('system') || 
                            p.user?.toLowerCase().includes('root') || 
                            p.user?.toLowerCase().includes('_mdns') || 
                            processLower === 'system' ||
                            processLower.includes('svchost') ||
                            processLower.includes('lsass') ||
                            processLower.includes('wininit') ||
                            processLower.includes('services') ||
                            processLower.includes('spoolsv') ||
                            processLower.includes('smss') ||
                            processLower.includes('csrss') ||
                            processLower.includes('winlogon') ||
                            false;
            const analysis = await apiInvoke<{ category: string; importance: string; safety: string; reasoning: string }>('analyze_port_local', {
              port: p.port,
              processName: p.process_name || 'unknown',
              isSystem: isSystem
            });
            newAnalyses[key] = analysis;
            changed = true;
          } catch (err) {
            console.error('Local ML Inference failed for port', p.port, err);
            // Fallback mockup classification if Tauri backend fails or outside Tauri environment
            const isCritical = p.port < 1024 || p.process_name?.toLowerCase().includes('system') || p.process_name?.toLowerCase().includes('svchost') || p.process_name?.toLowerCase().includes('mdns') || false;
            newAnalyses[key] = {
              category: isCritical ? 'System Service' : 'Dev Server',
              importance: isCritical ? 'CRITICAL' : 'DEVELOPMENT',
              safety: isCritical ? 'DANGEROUS_TO_KILL' : 'SAFE_TO_KILL',
              reasoning: isCritical 
                ? 'System user service detected. Terminating this process will cause system instability.'
                : 'User app server detected. Safe to kill if this port is no longer needed.'
            };
            changed = true;
          }
        }
      })
    );
    if (changed) {
      setPortAnalyses(newAnalyses);
    }
  };

  // Fetch active ports
  const fetchPorts = async () => {
    setIsLoading(true);
    setServerUnreachable(false);
    try {
      // Fetch active ports from adapter
      const activePorts = await apiInvoke<PortInfo[]>('get_active_ports');
      setPorts(activePorts);
      analyzePorts(activePorts);
    } catch (error) {
      console.error('Failed to get ports:', error);
      
      const isExtension = typeof window !== 'undefined' && window.location.protocol === 'chrome-extension:';
      if (isExtension) {
        setServerUnreachable(true);
      }

      // Fallback mockup data for browser development or if Tauri backend fails
      if (!(window as any).__TAURI_INTERNALS__) {
        const mockPorts = [
          { port: 3000, pid: 14201, process_name: 'node', protocol: 'TCP', user: 'dev_user' },
          { port: 5173, pid: 82023, process_name: 'vite', protocol: 'TCP', user: 'dev_user' },
          { port: 8080, pid: 9012, process_name: 'docker-proxy', protocol: 'TCP', user: 'root' },
          { port: 5432, pid: 412, process_name: 'postgres', protocol: 'TCP', user: 'postgres' },
          { port: 6379, pid: 885, process_name: 'redis-server', protocol: 'TCP', user: 'redis' },
          { port: 137, pid: 4, process_name: 'System', protocol: 'UDP', user: 'SYSTEM' },
          { port: 5353, pid: 890, process_name: 'mDNSResponder', protocol: 'UDP', user: '_mdnsresponder' },
        ];
        setPorts(mockPorts);
        analyzePorts(mockPorts);
      }
    } finally {
      setIsLoading(false);
    }
  };

  // Run on mount
  useEffect(() => {
    fetchPorts();
    // Auto refresh every 10 seconds
    const interval = setInterval(fetchPorts, 10000);
    return () => clearInterval(interval);
  }, []);



  // Filter ports based on search query
  const filteredPorts = useMemo(() => {
    return ports.filter(p => 
      p.port?.toString().includes(searchQuery) ||
      p.process_name?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      p.pid?.toString().includes(searchQuery) ||
      p.protocol?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      p.user?.toLowerCase().includes(searchQuery.toLowerCase())
    );
  }, [ports, searchQuery]);

  // Grouped Projects
  const groupedProjects = useMemo(() => {
    const groups: Record<string, { name: string; icon: any; count: number; color: string; ports: PortInfo[] }> = {
      web: { name: 'Web Dev Servers', icon: Globe, count: 0, color: 'from-blue-500 to-indigo-500', ports: [] },
      database: { name: 'Databases', icon: Database, count: 0, color: 'from-emerald-500 to-teal-500', ports: [] },
      docker: { name: 'Docker Containers', icon: Server, count: 0, color: 'from-cyan-500 to-sky-500', ports: [] },
      system: { name: 'System Daemons', icon: Cpu, count: 0, color: 'from-amber-500 to-orange-500', ports: [] },
      other: { name: 'Others', icon: Layers, count: 0, color: 'from-slate-500 to-slate-700', ports: [] },
    };

    ports.forEach(p => {
      const name = p.process_name?.toLowerCase() || '';
      if (name.includes('node') || name.includes('vite') || name.includes('next') || p.port === 3000 || p.port === 5173 || p.port === 80) {
        groups.web.count++;
        groups.web.ports.push(p);
      } else if (name.includes('postgres') || name.includes('sql') || name.includes('redis') || name.includes('mongo') || p.port === 5432 || p.port === 6379 || p.port === 3306) {
        groups.database.count++;
        groups.database.ports.push(p);
      } else if (name.includes('docker') || name.includes('container') || name.includes('proxy')) {
        groups.docker.count++;
        groups.docker.ports.push(p);
      } else if (name.includes('system') || name.includes('mdns') || name.includes('svchost') || name.includes('helper') || p.pid <= 100) {
        groups.system.count++;
        groups.system.ports.push(p);
      } else {
        groups.other.count++;
        groups.other.ports.push(p);
      }
    });

    return Object.values(groups).filter(g => g.count > 0);
  }, [ports]);

  // Helper to format termination error with detailed user-friendly explanations
  const getActionableErrorMessage = (err: string, procName: string) => {
    const errLower = err.toLowerCase();
    
    if (errLower.includes('access is denied') || errLower.includes('access_denied') || errLower.includes('permission denied')) {
      return (
        <div className="space-y-2">
          <p className="font-bold text-red-400">Access Denied (Privilege Restriction)</p>
          <p className="text-slate-300 text-[11px] leading-relaxed">
            PortIntel does not have the required system permissions to terminate <strong className="text-white">{procName}</strong>.
          </p>
          <div className="mt-1 pl-2 border-l border-red-500/40 text-slate-400 text-[11px] space-y-1">
            <span className="block">• <strong>Solution 1</strong>: Close PortIntel and relaunch it as <strong>Administrator</strong> (right-click and select "Run as Administrator").</span>
            <span className="block">• <strong>Solution 2</strong>: Sourced process might be a protected system service or third-party security software (antivirus, AnyDesk self-defense). Stop it via its official UI or Windows Services Manager (services.msc).</span>
          </div>
        </div>
      );
    }
    
    if (errLower.includes('not found') || errLower.includes('no such process')) {
      return (
        <div className="space-y-1">
          <p className="font-bold text-red-400">Process Already Terminated</p>
          <p className="text-slate-300 text-[11px]">
            The process <strong className="text-white">{procName}</strong> has already exited or changed its binding socket.
          </p>
        </div>
      );
    }
    
    return (
      <div className="space-y-1">
        <p className="font-bold text-red-400">Termination Failed</p>
        <p className="text-slate-300 text-[11px]">{err}</p>
      </div>
    );
  };

  // Kill process action
  const handleKillProcess = async () => {
    if (!portToKill) return;
    setIsKilling(true);
    setKillError(null);

    try {
      await apiInvoke('kill_process', { pid: portToKill.pid });
      
      const terminatedProcName = portToKill.process_name;
      const terminatedPort = portToKill.port;
      const terminatedPid = portToKill.pid;

      // Update local ports immediately
      setPorts(prev => prev.filter(p => p.pid !== portToKill.pid));
      setPortToKill(null);
      setKillConfirmInput('');

      // Show success toast
      setSuccessToast({
        show: true,
        message: 'Process Terminated Successfully',
        subMessage: `${terminatedProcName} (PID: ${terminatedPid}) binding port :${terminatedPort} has been killed.`
      });

      // Close drawer if it was inspecting the terminated port
      if (selectedPort && selectedPort.pid === terminatedPid) {
        setAiDrawerOpen(false);
      }
    } catch (err: any) {
      console.error(err);
      setKillError(err?.toString() || 'Failed to kill process. Access denied or process already terminated.');
      // Mockup simulation if outside Tauri environment
      if (!(window as any).__TAURI_INTERNALS__) {
        setPorts(prev => prev.filter(p => p.pid !== portToKill.pid));
        setPortToKill(null);
        setKillConfirmInput('');
      }
    } finally {
      setIsKilling(false);
    }
  };

  // Show Port Advisory
  const handleAskAI = async (port: PortInfo) => {
    setSelectedPort(port);
    setAiDrawerOpen(true);
    setAiLoading(true);
    setAiError(null);
    setSelectedAnalysis(null);

    const context: PortContext = {
      port: port.port,
      processName: port.process_name,
      pid: port.pid,
      protocol: port.protocol,
      user: port.user,
      os: os
    };

    try {
      // Introduce minor diagnostic delay for premium UX
      await new Promise(r => setTimeout(r, 200));
      const response = inspectPort(context);
      
      // Merge compiled-in ONNX classifications if available
      const onnxKey = `${port.port}-${port.pid}`;
      const onnxAnalysis = portAnalyses[onnxKey];
      if (onnxAnalysis) {
        response.category = onnxAnalysis.category as any;
        response.safety = onnxAnalysis.category === 'Remote Access' 
          ? 'Caution' 
          : (onnxAnalysis.safety === 'DANGEROUS_TO_KILL' ? 'Dangerous' : 'Safe');
        response.description = onnxAnalysis.reasoning;
        response.recommendation = onnxAnalysis.safety === 'DANGEROUS_TO_KILL'
          ? 'System core binding. Terminating this service is restricted by safety policy.'
          : (onnxAnalysis.category === 'Remote Access'
              ? 'Remote desktop sharing daemon. Proceed with caution to avoid dropping active remote connections.'
              : 'User application server or utility. Safe to terminate to free up socket resources.');
      }

      setSelectedAnalysis(response);

      // Save to logs
      const newLog: DiagnosticLog = {
        id: Math.random().toString(36).substring(2, 11),
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
        port: port.port,
        processName: port.process_name,
        pid: port.pid,
        protocol: port.protocol,
        analysis: JSON.stringify(response),
        followUps: []
      };

      const updatedLogs = [newLog, ...diagnosticLogs].slice(0, 50); // Keep last 50 logs
      setDiagnosticLogs(updatedLogs);
      localStorage.setItem('portintel_diagnostic_logs', JSON.stringify(updatedLogs));

    } catch (err: any) {
      setAiError(err?.message || 'Error occurred while running local diagnostics.');
    } finally {
      setAiLoading(false);
    }
  };

  // Load log history
  const handleViewHistoricalLog = (log: DiagnosticLog) => {
    const mockPort: PortInfo = {
      port: log.port,
      pid: log.pid,
      process_name: log.processName,
      protocol: log.protocol,
      user: 'N/A'
    };
    setSelectedPort(mockPort);
    setAiDrawerOpen(true);
    setAiError(null);
    
    try {
      const parsed = JSON.parse(log.analysis);
      setSelectedAnalysis(parsed);
    } catch (e) {
      setAiError('Failed to load archived diagnostic data.');
    }
  };

  if (serverUnreachable) {
    return (
      <div className="flex h-screen w-screen flex-col items-center justify-center bg-slate-950 p-6 font-sans text-slate-100 antialiased animate-fade-in">
        <div className="max-w-md w-full rounded-2xl border border-slate-800 bg-slate-900/60 p-8 text-center backdrop-blur-md shadow-2xl relative overflow-hidden">
          <div className="absolute -right-10 -top-10 h-32 w-32 rounded-full bg-gradient-to-tr from-brand-600 to-cyan-500 opacity-5 blur-2xl animate-pulse" />
          <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-full bg-brand-500/10 text-brand-400 mb-6">
            <Activity className="h-8 w-8 animate-glow" />
          </div>
          <h2 className="text-xl font-bold tracking-tight text-slate-100 font-sans">Desktop App Offline</h2>
          <p className="text-sm text-slate-400 mt-3 leading-relaxed font-sans font-medium">
            The PortIntel extension requires the desktop application to be running in order to scan system sockets and manage active ports.
          </p>
          <div className="mt-6 p-4 rounded-xl bg-slate-950/80 border border-slate-800/60 text-xs text-left text-slate-500 space-y-2 font-sans">
            <span className="block font-bold text-slate-400">To resolve this:</span>
            <span className="block">• Open your native **PortIntel** desktop application.</span>
            <span className="block">• The desktop background agent will automatically start listening.</span>
          </div>
          <button
            onClick={fetchPorts}
            className="mt-6 w-full flex items-center justify-center space-x-2 rounded-lg bg-brand-600 hover:bg-brand-500 py-2.5 text-sm font-semibold text-white transition-all shadow-lg shadow-brand-500/20 font-sans"
          >
            <RefreshCw className={`h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
            <span>Retry Connection</span>
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-slate-950 font-sans text-slate-100 antialiased">
      
      {/* MOBILE SIDEBAR OVERLAY */}
      {mobileSidebarOpen && (
        <div className="fixed inset-0 z-45 flex md:hidden">
          {/* Backdrop */}
          <div 
            onClick={() => setMobileSidebarOpen(false)}
            className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm transition-opacity" 
          />
          
          {/* Floating Sidebar Sheet */}
          <aside className="relative flex w-64 max-w-xs flex-col bg-slate-900 border-r border-slate-850 p-4 justify-between h-full z-50 animate-slide-in">
            <div className="space-y-6">
              {/* Logo & Close Button */}
              <div className="flex items-center justify-between px-2">
                <div className="flex items-center space-x-3">
                  <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-gradient-to-tr from-brand-600 to-cyan-500 shadow-lg shadow-brand-500/20">
                    <Activity className="h-5 w-5 text-white" />
                  </div>
                  <div>
                    <span className="text-lg font-bold tracking-tight bg-gradient-to-r from-white to-slate-400 bg-clip-text text-transparent">PortIntel</span>
                  </div>
                </div>
                <button 
                  onClick={() => setMobileSidebarOpen(false)}
                  className="text-slate-400 hover:text-slate-200"
                >
                  <X className="h-5 w-5" />
                </button>
              </div>

              {/* Navigation */}
              <nav className="space-y-1">
                <button 
                  onClick={() => { setActiveTab('all'); setMobileSidebarOpen(false); }}
                  className={`flex w-full items-center space-x-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-all duration-200 ${activeTab === 'all' ? 'bg-brand-600/20 text-brand-400 border border-brand-500/30' : 'text-slate-400 hover:bg-slate-800/50 hover:text-slate-200 border border-transparent'}`}
                >
                  <Terminal className="h-4.5 w-4.5" />
                  <span>All Active Ports</span>
                  <span className="ml-auto rounded bg-slate-800 px-1.5 py-0.5 text-xs text-slate-400">{ports.length}</span>
                </button>
                <button 
                  onClick={() => { setActiveTab('projects'); setMobileSidebarOpen(false); }}
                  className={`flex w-full items-center space-x-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-all duration-200 ${activeTab === 'projects' ? 'bg-brand-600/20 text-brand-400 border border-brand-500/30' : 'text-slate-400 hover:bg-slate-800/50 hover:text-slate-200 border border-transparent'}`}
                >
                  <Folder className="h-4.5 w-4.5" />
                  <span>Grouped Projects</span>
                  <span className="ml-auto rounded bg-slate-800 px-1.5 py-0.5 text-xs text-slate-400">{groupedProjects.length}</span>
                </button>
                <button 
                  onClick={() => { setActiveTab('logs'); setMobileSidebarOpen(false); }}
                  className={`flex w-full items-center space-x-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-all duration-200 ${activeTab === 'logs' ? 'bg-brand-600/20 text-brand-400 border border-brand-500/30' : 'text-slate-400 hover:bg-slate-800/50 hover:text-slate-200 border border-transparent'}`}
                >
                  <History className="h-4.5 w-4.5" />
                  <span>Diagnostic History</span>
                  <span className="ml-auto rounded bg-slate-800 px-1.5 py-0.5 text-xs text-slate-400">{diagnosticLogs.length}</span>
                </button>
              </nav>
            </div>

            <div className="space-y-4 pt-4 border-t border-slate-800">
              <div className="px-3 py-2 rounded-lg bg-slate-950 border border-slate-800/40 text-[11px] text-slate-500">
                <span className="block font-semibold">OS Engine:</span>
                <span className="block font-mono mt-0.5 text-slate-400">{os === 'macos' ? 'macOS (lsof)' : os === 'windows' ? 'Windows (netstat)' : 'Linux (lsof)'}</span>
              </div>
            </div>
          </aside>
        </div>
      )}
      
      {/* DESKTOP SIDEBAR */}
      <aside className="w-64 border-r border-slate-800 bg-slate-900/60 p-4 hidden md:flex flex-col justify-between backdrop-blur-md">
        <div className="space-y-6">
          {/* Logo */}
          <div className="flex items-center space-x-3 px-2">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-gradient-to-tr from-brand-600 to-cyan-500 shadow-lg shadow-brand-500/20">
              <Activity className="h-5 w-5 text-white" />
            </div>
            <div>
              <span className="text-lg font-bold tracking-tight bg-gradient-to-r from-white to-slate-400 bg-clip-text text-transparent">PortIntel</span>
              <span className="block text-[10px] text-slate-500 font-semibold tracking-wider uppercase">V2 PROT DETECT</span>
            </div>
          </div>

          {/* Navigation */}
          <nav className="space-y-1">
            <button 
              onClick={() => setActiveTab('all')}
              className={`flex w-full items-center space-x-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-all duration-200 ${activeTab === 'all' ? 'bg-brand-600/20 text-brand-400 border border-brand-500/30' : 'text-slate-400 hover:bg-slate-800/50 hover:text-slate-200 border border-transparent'}`}
            >
              <Terminal className="h-4.5 w-4.5" />
              <span>All Active Ports</span>
              <span className="ml-auto rounded bg-slate-800 px-1.5 py-0.5 text-xs text-slate-400">{ports.length}</span>
            </button>
            <button 
              onClick={() => setActiveTab('projects')}
              className={`flex w-full items-center space-x-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-all duration-200 ${activeTab === 'projects' ? 'bg-brand-600/20 text-brand-400 border border-brand-500/30' : 'text-slate-400 hover:bg-slate-800/50 hover:text-slate-200 border border-transparent'}`}
            >
              <Folder className="h-4.5 w-4.5" />
              <span>Grouped Projects</span>
              <span className="ml-auto rounded bg-slate-800 px-1.5 py-0.5 text-xs text-slate-400">{groupedProjects.length}</span>
            </button>
            <button 
              onClick={() => setActiveTab('logs')}
              className={`flex w-full items-center space-x-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-all duration-200 ${activeTab === 'logs' ? 'bg-brand-600/20 text-brand-400 border border-brand-500/30' : 'text-slate-400 hover:bg-slate-800/50 hover:text-slate-200 border border-transparent'}`}
            >
              <History className="h-4.5 w-4.5" />
              <span>Diagnostic History</span>
              <span className="ml-auto rounded bg-slate-800 px-1.5 py-0.5 text-xs text-slate-400">{diagnosticLogs.length}</span>
            </button>
          </nav>
        </div>

        {/* Footer Sidebar Settings */}
        <div className="space-y-4 pt-4 border-t border-slate-800">

          <div className="px-3 py-2 rounded-lg bg-slate-950 border border-slate-800/40 text-[11px] text-slate-500">
            <span className="block font-semibold">OS Engine:</span>
            <span className="block font-mono mt-0.5 text-slate-400">{os === 'macos' ? 'macOS (lsof)' : os === 'windows' ? 'Windows (netstat)' : 'Linux (lsof)'}</span>
          </div>
        </div>
      </aside>

      {/* MAIN CONTAINER */}
      <main className="flex-1 flex flex-col overflow-hidden bg-slate-950 relative">
        
        {/* TOP BAR */}
        <header className="h-16 border-b border-slate-800/60 bg-slate-900/20 px-4 md:px-6 flex items-center justify-between backdrop-blur-md z-10 gap-4 flex-shrink-0">
          <div className="flex items-center space-x-3 min-w-0 flex-1">
            <button 
              onClick={() => setMobileSidebarOpen(true)}
              className="p-1.5 rounded-lg border border-slate-800 bg-slate-900 text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition md:hidden flex-shrink-0"
            >
              <Menu className="h-5 w-5" />
            </button>
            <h1 className="text-base sm:text-lg lg:text-xl font-bold tracking-tight truncate">
              {activeTab === 'all' && 'Active Network Connections'}
              {activeTab === 'projects' && 'Grouped Network Projects'}
              {activeTab === 'logs' && 'Diagnostic Archives'}
            </h1>
          </div>

          <div className="flex items-center space-x-2 sm:space-x-3 flex-shrink-0">
            {/* Search */}
            <div className="relative w-28 xs:w-36 sm:w-48 lg:w-64">
              <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-slate-500" />
              <input 
                type="text"
                placeholder="Search..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full rounded-lg bg-slate-900/80 border border-slate-800 py-1.5 pl-8 pr-3 text-xs sm:text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-brand-500 focus:border-brand-500 transition-all"
              />
            </div>

            {/* Refresh */}
            <button 
              onClick={fetchPorts}
              disabled={isLoading}
              className="flex items-center space-x-1.5 rounded-lg bg-slate-900 border border-slate-800 hover:bg-slate-800 px-2.5 py-1.5 text-xs sm:text-sm font-medium text-slate-300 transition-all disabled:opacity-50"
            >
              <RefreshCw className={`h-3.5 w-3.5 text-slate-400 ${isLoading ? 'animate-spin' : ''}`} />
              <span className="hidden lg:inline">Refresh</span>
            </button>

            {/* Global Diagnostic Toggle */}
            <div className="flex items-center space-x-2 border-l border-slate-800 pl-2 sm:pl-3">
              <span className="text-xs text-slate-400 font-medium hidden lg:inline">ML Diagnostics</span>
              <button 
                onClick={() => setAiEnabled(!aiEnabled)}
                className={`relative inline-flex h-5 w-9 sm:h-6 sm:w-11 items-center rounded-full transition-all duration-300 focus:outline-none ${aiEnabled ? 'bg-brand-500' : 'bg-slate-800'}`}
              >
                <span className={`inline-block h-3 w-3 sm:h-4 sm:w-4 transform rounded-full bg-white transition-all duration-300 ${aiEnabled ? 'translate-x-5 sm:translate-x-6' : 'translate-x-1'}`} />
              </button>
            </div>
          </div>
        </header>

        {/* MAIN PANEL */}
        <section className="flex-1 overflow-y-auto p-4 md:p-6">
          
          {/* TAB 1: ALL ACTIVE PORTS */}
          {activeTab === 'all' && (
            <div className="rounded-xl border border-slate-800/80 bg-slate-900/20 backdrop-blur-md overflow-hidden">
              <div className="overflow-x-auto w-full">
                <table className="w-full text-left border-collapse min-w-[800px] xl:min-w-0">
                  <thead>
                    <tr className="border-b border-slate-800 bg-slate-900/40 text-xs font-semibold uppercase tracking-wider text-slate-400">
                      <th className="py-3 px-4 w-24 sm:w-28">Port</th>
                      <th className="py-3 px-4">Process Name</th>
                      <th className="py-3 px-4 w-20 sm:w-28">PID</th>
                      <th className="py-3 px-4 w-20 sm:w-24 hidden lg:table-cell">Protocol</th>
                      <th className="py-3 px-4 w-28 sm:w-32 hidden md:table-cell">Importance</th>
                      <th className="py-3 px-4 hidden xl:table-cell">Action Advisory</th>
                      <th className="py-3 px-4 text-right w-36 sm:w-44">Actions</th>
                    </tr>
                  </thead>
                <tbody className="divide-y divide-slate-800/40 text-sm">
                  {isLoading && ports.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="py-12 text-center text-slate-500">
                        <RefreshCw className="h-6 w-6 animate-spin mx-auto mb-2 text-slate-400" />
                        Fetching network tables...
                      </td>
                    </tr>
                  ) : filteredPorts.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="py-12 text-center text-slate-500">
                        <Info className="h-6 w-6 mx-auto mb-2 text-slate-500" />
                        No active ports found matching search criteria.
                      </td>
                    </tr>
                  ) : (
                    filteredPorts.map((port) => {
                      const key = `${port.port}-${port.pid}`;
                      const analysis = portAnalyses[key];
                      const isCritical = analysis?.importance === 'CRITICAL';
                      const isDangerousToKill = analysis?.safety === 'DANGEROUS_TO_KILL';
                      
                      return (
                        <tr 
                          key={`${port.port}-${port.pid}-${port.protocol}`}
                          className="hover:bg-slate-900/30 transition-colors duration-150 group"
                        >
                          <td className="py-3 px-4">
                            <span className={`inline-flex items-center justify-center font-mono font-bold text-xs px-2.5 py-1 rounded-md border ${
                              port.protocol === 'TCP' 
                                ? 'bg-brand-950/40 border-brand-500/20 text-brand-400' 
                                : 'bg-purple-950/40 border-purple-500/20 text-purple-400'
                            }`}>
                              :{port.port}
                            </span>
                          </td>
                          <td className="py-3 px-4">
                            <span className="font-semibold text-slate-200 block">{port.process_name}</span>
                            {port.memory && (
                              <span className="text-[10px] text-slate-500 font-mono mt-0.5 block">{port.memory}</span>
                            )}
                          </td>
                          <td className="py-3 px-4 font-mono text-slate-400">
                            {port.pid}
                          </td>
                          <td className="py-3 px-4 hidden lg:table-cell">
                            <span className="text-xs text-slate-400 font-mono font-semibold">{port.protocol}</span>
                          </td>
                          <td className="py-3 px-4 hidden md:table-cell">
                            {analysis ? (
                              <span className={`inline-flex items-center space-x-1.5 px-2 py-0.5 rounded text-[11px] font-bold tracking-wide uppercase border ${
                                isCritical 
                                  ? 'bg-amber-950/40 border-amber-500/30 text-amber-400 animate-pulse'
                                  : analysis.importance === 'DEVELOPMENT'
                                    ? 'bg-emerald-950/40 border-emerald-500/30 text-emerald-400'
                                    : 'bg-slate-800 border-slate-700 text-slate-400'
                              }`}>
                                <Shield className="h-3 w-3" />
                                <span>{analysis.importance}</span>
                              </span>
                            ) : (
                              <span className="text-xs text-slate-600 animate-pulse">Scanning...</span>
                            )}
                          </td>
                          <td className="py-3 px-4 text-xs text-slate-400 max-w-xs truncate hidden xl:table-cell" title={analysis?.reasoning}>
                            {analysis ? (
                              <span className="flex items-center space-x-1.5">
                                <span className={`h-1.5 w-1.5 rounded-full ${isDangerousToKill ? 'bg-red-500 animate-ping' : 'bg-emerald-500'}`} />
                                <span className="truncate">{analysis.reasoning}</span>
                              </span>
                            ) : (
                              <span className="text-slate-600">Retrieving advisory...</span>
                            )}
                          </td>
                          <td className="py-3 px-4 text-right">
                            <div className="flex items-center justify-end space-x-2">
                              {aiEnabled && (
                                <button 
                                  onClick={() => handleAskAI(port)}
                                  className="flex items-center space-x-1 rounded-md bg-brand-600/10 hover:bg-brand-600/20 border border-brand-500/20 hover:border-brand-500/40 px-2.5 py-1.5 text-xs text-brand-300 font-semibold transition-all duration-200"
                                >
                                  <Info className="h-3.5 w-3.5" />
                                  <span>Inspect</span>
                                </button>
                              )}
                              
                              {isDangerousToKill ? (
                                <button 
                                  disabled
                                  title="System safety override active. Terminating critical operating services is restricted to prevent crash cycles."
                                  className="flex items-center space-x-1 rounded-md bg-slate-900 border border-slate-800/40 px-2.5 py-1.5 text-xs text-slate-600 font-semibold cursor-not-allowed"
                                >
                                  <Trash2 className="h-3.5 w-3.5 text-slate-600" />
                                  <span>Restricted</span>
                                </button>
                              ) : (
                                <button 
                                  onClick={() => {
                                    setPortToKill(port);
                                    setKillConfirmInput('');
                                    setKillError(null);
                                  }}
                                  className="flex items-center space-x-1 rounded-md bg-red-950/20 hover:bg-red-600 hover:text-white border border-red-900/30 hover:border-red-600 px-2.5 py-1.5 text-xs text-red-400 font-semibold transition-all duration-200"
                                >
                                  <Trash2 className="h-3.5 w-3.5" />
                                  <span>Kill</span>
                                </button>
                              )}
                            </div>
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
              </div>
            </div>
          )}

          {/* TAB 2: GROUPED PROJECTS */}
          {activeTab === 'projects' && (
            <div className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {groupedProjects.map((group) => {
                  const Icon = group.icon;
                  return (
                    <div 
                      key={group.name}
                      className="rounded-xl border border-slate-800/80 bg-slate-900/30 p-5 hover:border-slate-700/60 transition-all duration-300 relative overflow-hidden group"
                    >
                      {/* Accent glow */}
                      <div className={`absolute -right-10 -top-10 h-32 w-32 rounded-full bg-gradient-to-tr ${group.color} opacity-5 blur-2xl group-hover:opacity-10 transition-opacity`} />
                      
                      <div className="flex items-start justify-between">
                        <div className={`p-2.5 rounded-lg bg-gradient-to-tr ${group.color} bg-opacity-20 text-white shadow-md`}>
                          <Icon className="h-5 w-5" />
                        </div>
                        <span className="text-2xl font-extrabold text-slate-300">{group.count}</span>
                      </div>
                      
                      <h3 className="text-base font-bold text-slate-200 mt-4">{group.name}</h3>
                      <p className="text-xs text-slate-400 mt-1">Active instances running on native ports.</p>
                      
                      <div className="mt-4 pt-4 border-t border-slate-800/50 space-y-2 max-h-48 overflow-y-auto">
                        {group.ports.map((port) => (
                          <div key={`${port.port}-${port.pid}`} className="flex items-center justify-between text-xs py-1.5 hover:bg-slate-800/30 px-1 rounded transition">
                            <div className="flex flex-col">
                              <span className="font-mono font-bold text-brand-400">:{port.port}</span>
                              {port.memory && (
                                <span className="text-[9px] text-slate-500 font-mono mt-0.5">{port.memory}</span>
                              )}
                            </div>
                            <span className="text-slate-300 font-semibold">{port.process_name}</span>
                            <span className="text-slate-500 font-mono">PID {port.pid}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* TAB 3: DIAGNOSTICS ARCHIVE */}
          {activeTab === 'logs' && (
            <div className="space-y-4">
              {diagnosticLogs.length === 0 ? (
                <div className="rounded-xl border border-slate-800 bg-slate-900/10 p-8 text-center text-slate-500">
                  <History className="h-8 w-8 mx-auto mb-2 text-slate-600" />
                  No local diagnostic records stored yet.
                  <p className="text-xs text-slate-600 mt-1">Ask the AI Assistant about active processes to build up logs.</p>
                </div>
              ) : (
                <div className="grid gap-4">
                  {diagnosticLogs.map((log) => (
                    <div 
                      key={log.id} 
                      className="rounded-xl border border-slate-800/60 bg-slate-900/30 p-4 hover:border-slate-700/60 transition-all flex flex-col md:flex-row justify-between items-start md:items-center space-y-4 md:space-y-0"
                    >
                      <div className="space-y-1.5">
                        <div className="flex items-center space-x-2">
                          <span className="text-xs font-mono bg-brand-950/40 border border-brand-500/20 text-brand-400 font-bold px-2 py-0.5 rounded">
                            :{log.port}
                          </span>
                          <span className="text-sm font-bold text-slate-200">{log.processName}</span>
                          <span className="text-xs text-slate-500 font-mono">(PID: {log.pid})</span>
                        </div>
                        <p className="text-xs text-slate-400 line-clamp-1 max-w-2xl">
                          {(() => {
                            try {
                              const parsed = JSON.parse(log.analysis);
                              const safetyColor = parsed.safety === 'Dangerous' ? 'text-red-400 font-bold' : parsed.safety === 'Caution' ? 'text-amber-400 font-bold' : 'text-emerald-400 font-bold';
                              return (
                                <>
                                  <span className={safetyColor}>[{parsed.safety.toUpperCase()}]</span>{' '}
                                  <span className="text-slate-300 font-medium">({parsed.category})</span>{' '}
                                  <span>{parsed.description}</span>
                                </>
                              );
                            } catch (e) {
                              return log.analysis;
                            }
                          })()}
                        </p>
                        <div className="text-[11px] text-slate-500">
                          <span>Analyzed at {log.timestamp}</span>
                        </div>
                      </div>
                      
                      <button 
                        onClick={() => handleViewHistoricalLog(log)}
                        className="flex items-center space-x-1.5 rounded-md bg-slate-800 hover:bg-slate-700 border border-slate-700 px-3 py-1.5 text-xs text-slate-300 font-semibold transition"
                      >
                        <Eye className="h-3.5 w-3.5" />
                        <span>View Insights</span>
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

        </section>

        {/* BOTTOM STATUS BAR */}
        <footer className="h-10 border-t border-slate-800 bg-slate-950 px-6 flex items-center justify-between text-xs text-slate-500">
          <div className="flex items-center space-x-4">
            <span>Active Ports: <strong className="text-slate-400">{ports.length}</strong></span>
            <span>•</span>
            <span>Process Count: <strong className="text-slate-400">{new Set(ports.map(p => p.pid)).size}</strong></span>
          </div>

          <div className="flex items-center space-x-2">
            <div className="h-2 w-2 rounded-full bg-emerald-500 shadow-sm shadow-emerald-500/30" />
            <span>Model Status: </span>
            <strong className="text-slate-400 uppercase font-mono">
              Decision Tree (ONNX Native)
            </strong>
          </div>
        </footer>

        {/* KILL CONFIRMATION DIALOG */}
        {portToKill && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
            <div className="w-full max-w-md rounded-xl border border-red-500/30 bg-slate-900 p-6 shadow-2xl relative overflow-hidden">
              {/* Warning strip */}
              <div className="absolute top-0 left-0 right-0 h-1 bg-red-500" />
              
              <div className="flex items-start space-x-3">
                <div className="p-2 rounded-lg bg-red-500/10 text-red-500">
                  <AlertTriangle className="h-6 w-6" />
                </div>
                <div>
                  <h3 className="text-lg font-bold text-slate-100">Force Kill Process?</h3>
                  <p className="text-sm text-slate-400 mt-1">
                    You are attempting to kill <strong className="text-red-400">{portToKill.process_name}</strong> (PID: <strong className="text-slate-300 font-mono">{portToKill.pid}</strong>) binding port <strong className="text-brand-400 font-mono">:{portToKill.port}</strong>.
                  </p>
                </div>
              </div>

              <div className="mt-4 p-3 rounded bg-slate-950 border border-slate-800 text-xs text-slate-400">
                <span className="block font-semibold text-slate-300">Potential Side Effects:</span>
                Force-terminating processes can result in uncommitted file data loss or local service state corruption.
              </div>

              {killError && (
                <div className="mt-3 p-3.5 rounded-lg bg-red-950/20 border border-red-900/40 text-xs font-medium">
                  {getActionableErrorMessage(killError, portToKill.process_name)}
                </div>
              )}

              <div className="mt-4">
                <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                  Type <span className="font-mono text-red-400 select-all font-bold">kill</span> to confirm:
                </label>
                <input 
                  type="text"
                  placeholder="kill"
                  value={killConfirmInput}
                  onChange={(e) => setKillConfirmInput(e.target.value)}
                  className="w-full rounded-lg bg-slate-950 border border-slate-800 py-2 px-3 text-sm text-slate-200 focus:outline-none focus:ring-1 focus:ring-red-500 focus:border-red-500"
                />
              </div>

              <div className="mt-6 flex space-x-3 justify-end">
                <button 
                  onClick={() => setPortToKill(null)}
                  disabled={isKilling}
                  className="rounded-lg bg-slate-800 hover:bg-slate-700 px-4 py-2 text-sm font-semibold text-slate-300 transition"
                >
                  Cancel
                </button>
                <button 
                  onClick={handleKillProcess}
                  disabled={killConfirmInput !== 'kill' || isKilling}
                  className="rounded-lg bg-red-600 hover:bg-red-500 disabled:opacity-50 disabled:hover:bg-red-600 px-4 py-2 text-sm font-semibold text-white transition flex items-center space-x-1.5"
                >
                  {isKilling ? (
                    <RefreshCw className="h-4 w-4 animate-spin" />
                  ) : (
                    <Trash2 className="h-4 w-4" />
                  )}
                  <span>Terminate Process</span>
                </button>
              </div>
            </div>
          </div>
        )}



        {/* DIAGNOSTIC DETAILS DRAWER OVERLAY */}
        {aiDrawerOpen && (
          <div 
            onClick={() => setAiDrawerOpen(false)}
            className="fixed inset-0 bg-slate-950/40 backdrop-blur-xs z-30 lg:hidden"
          />
        )}

        {/* DIAGNOSTIC DETAILS DRAWER */}
        <div className={`fixed top-0 right-0 h-full w-full sm:w-[450px] z-40 bg-slate-900 border-l border-slate-800 shadow-2xl flex flex-col justify-between transform transition-transform duration-300 ease-in-out ${aiDrawerOpen ? 'translate-x-0' : 'translate-x-full'}`}>
          {/* Drawer Header */}
          <div className="p-4 border-b border-slate-800/80 bg-slate-950/40 flex items-center justify-between">
            <div className="flex items-center space-x-2 text-brand-400">
              <Info className="h-5 w-5" />
              <div>
                <h3 className="font-bold text-slate-200">Port Diagnostics</h3>
                {selectedPort && (
                  <span className="block text-[11px] text-slate-400 font-mono mt-0.5">
                    Port :{selectedPort.port} | {selectedPort.process_name} (PID: {selectedPort.pid})
                  </span>
                )}
              </div>
            </div>
            <button 
              onClick={() => setAiDrawerOpen(false)}
              className="text-slate-400 hover:text-slate-200 p-1.5 rounded-lg hover:bg-slate-800 transition"
            >
              <X className="h-5 w-5" />
            </button>
          </div>

          {/* Drawer Message Body */}
          <div className="flex-1 overflow-y-auto p-5 space-y-5">
            {aiLoading ? (
              <div className="flex flex-col items-center justify-center h-full text-slate-500 text-center space-y-3">
                <div className="relative">
                  <div className="h-10 w-10 rounded-full border-2 border-brand-500/20 border-t-brand-500 animate-spin" />
                  <Info className="h-4 w-4 text-brand-400 absolute inset-0 m-auto" />
                </div>
                <div>
                  <span className="font-bold block text-sm text-slate-300">Analyzing Port...</span>
                  <span className="text-xs text-slate-500 block mt-1">Running local heuristics and ML inference</span>
                </div>
              </div>
            ) : aiError ? (
              <div className="flex flex-col items-center justify-center h-full text-slate-500 text-center p-4">
                <div className="rounded-lg bg-red-950/30 border border-red-900/50 p-4 text-xs text-red-400 font-medium text-left max-w-sm">
                  <span className="block font-bold mb-1 text-sm">Diagnostic Fault:</span>
                  {aiError}
                </div>
              </div>
            ) : selectedAnalysis ? (
              <div className="space-y-5">
                {/* Status Badges */}
                <div className="flex items-center justify-between border-b border-slate-800/60 pb-3">
                  <span className="text-xs font-bold uppercase tracking-wider text-slate-500">
                    Diagnostic Report
                  </span>
                  <span className={`inline-flex items-center px-2.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border ${
                    selectedAnalysis.safety === 'Dangerous' || selectedAnalysis.safety === 'Dangerous to Kill'
                      ? 'bg-red-950/40 border-red-500/30 text-red-400'
                      : selectedAnalysis.safety === 'Caution'
                        ? 'bg-amber-950/40 border-amber-500/30 text-amber-400'
                        : 'bg-emerald-950/40 border-emerald-500/30 text-emerald-400'
                  }`}>
                    {selectedAnalysis.safety === 'Dangerous' || selectedAnalysis.safety === 'Dangerous to Kill'
                      ? 'Protected / Do Not Kill'
                      : selectedAnalysis.safety === 'Caution'
                        ? 'Caution Required'
                        : 'Safe to Terminate'}
                  </span>
                </div>

                {/* Details Section */}
                <div className="space-y-4 text-sm">
                  <div className="grid grid-cols-2 gap-4 bg-slate-950/40 border border-slate-900 rounded-lg p-3">
                    <div>
                      <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block">Port binding</span>
                      <span className="font-mono font-bold text-brand-400">:{selectedPort?.port} ({selectedPort?.protocol})</span>
                    </div>
                    <div>
                      <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block">Process ID</span>
                      <span className="font-mono text-slate-300">{selectedPort?.pid}</span>
                    </div>
                    <div>
                      <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block">Process Name</span>
                      <span className="font-semibold text-slate-300">{selectedPort?.process_name}</span>
                    </div>
                    <div>
                      <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block">User Owner</span>
                      <span className="text-slate-300">{selectedPort?.user}</span>
                    </div>
                    {selectedPort?.memory && (
                      <div className="col-span-2 border-t border-slate-900/60 pt-2.5 mt-0.5">
                        <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block">Memory Footprint</span>
                        <span className="text-xs font-mono text-slate-300 block mt-0.5">{selectedPort.memory}</span>
                      </div>
                    )}
                  </div>

                  <div className="space-y-1">
                    <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block">Classification</span>
                    <div>
                      <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-bold tracking-wide uppercase border bg-slate-800 border-slate-700 text-slate-300">
                        {selectedAnalysis.category}
                      </span>
                    </div>
                  </div>

                  <div className="space-y-1">
                    <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block">Description</span>
                    <p className="text-slate-300 leading-relaxed text-xs">{selectedAnalysis.description}</p>
                  </div>

                  <div className="space-y-1">
                    <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block">Advisory & Recommendation</span>
                    <p className="text-slate-300 leading-relaxed text-xs">{selectedAnalysis.recommendation}</p>
                  </div>

                  <div className="pt-3 border-t border-slate-850 space-y-2">
                    <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block">Graceful Stop Command</span>
                    <div className="flex items-center justify-between bg-slate-950 border border-slate-850 rounded px-2.5 py-1.5 font-mono text-xs text-slate-300">
                      <span className="truncate select-all">{selectedAnalysis.gracefulCommand}</span>
                      <button
                        onClick={() => navigator.clipboard.writeText(selectedAnalysis.gracefulCommand)}
                        className="text-brand-400 hover:text-brand-300 font-bold uppercase text-[10px] pl-2.5 border-l border-slate-800 shrink-0"
                      >
                        Copy
                      </button>
                    </div>
                  </div>
                </div>

                {/* Direct Action Button in Drawer */}
                <div className="pt-5 border-t border-slate-850">
                  {selectedAnalysis.safety === 'Dangerous' || selectedAnalysis.safety === 'Dangerous to Kill' || selectedAnalysis.safety === 'DANGEROUS_TO_KILL' ? (
                    <div className="flex items-center space-x-2 text-xs text-slate-500 bg-slate-950/60 border border-slate-900 rounded-lg p-3">
                      <Shield className="h-5 w-5 text-red-500 shrink-0" />
                      <span>This is a critical system dependency. Direct termination is disabled to prevent workstation crashes.</span>
                    </div>
                  ) : (
                    <button
                      onClick={() => {
                        if (selectedPort) {
                          setPortToKill(selectedPort);
                          setKillConfirmInput('');
                          setKillError(null);
                        }
                      }}
                      className="w-full flex items-center justify-center space-x-2 rounded-lg bg-red-650 hover:bg-red-600 hover:text-white py-2.5 text-xs font-semibold text-red-200 transition"
                    >
                      <Trash2 className="h-4 w-4" />
                      <span>Terminate Process Binding</span>
                    </button>
                  )}
                </div>
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center h-full text-slate-500 text-center">
                <Info className="h-8 w-8 text-slate-600 mb-2" />
                <span>No port selected</span>
              </div>
            )}
          </div>
        </div>

        {/* SUCCESS TOAST NOTIFICATION */}
        {successToast && successToast.show && (
          <div className="fixed top-6 right-6 z-50 flex items-center space-x-3 bg-slate-900/90 backdrop-blur border border-emerald-500/30 rounded-xl p-4 shadow-2xl animate-slide-in max-w-sm">
            <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400">
              <CheckCircle className="h-5 w-5" />
            </div>
            <div className="flex-1 min-w-0">
              <h4 className="font-bold text-xs text-slate-100">{successToast.message}</h4>
              {successToast.subMessage && (
                <p className="text-[10px] text-slate-400 mt-0.5 leading-normal select-text selection:bg-brand-500">{successToast.subMessage}</p>
              )}
            </div>
            <button 
              onClick={() => setSuccessToast(null)}
              className="text-slate-500 hover:text-slate-300 transition shrink-0 self-start mt-0.5"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        )}

      </main>
    </div>
  );
}
