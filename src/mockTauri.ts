// Inject Tauri browser-mode mock if running in a standard web browser
if (typeof window !== 'undefined' && !(window as any).__TAURI_INTERNALS__) {
  const mockPorts = [
    { port: 3000, pid: 14201, process_name: 'node', protocol: 'TCP', user: 'dev_user' },
    { port: 5173, pid: 18920, process_name: 'vite', protocol: 'TCP', user: 'dev_user' },
    { port: 8080, pid: 2100, process_name: 'nginx', protocol: 'TCP', user: 'system' },
    { port: 50001, pid: 4496, process_name: 'AnyDesk.exe', protocol: 'TCP', user: 'dev_user' },
    { port: 9222, pid: 1022, process_name: 'chrome.exe', protocol: 'TCP', user: 'dev_user' }
  ];
  
  const mockAnalyze = (_port: number, processName: string) => {
    const name = (processName || '').toLowerCase();
    
    let category = 'Unknown';
    let importance = 'UNKNOWN/SUSPICIOUS';
    let safety = 'SAFE_TO_KILL';
    let reasoning = 'Unknown user space connection. Safe to kill if this port binding is no longer needed.';

    if (name.includes('node') || name.includes('vite')) {
      category = 'Dev Server';
      importance = 'DEVELOPMENT';
      safety = 'SAFE_TO_KILL';
      reasoning = 'User development environment or application server. Safe to terminate to free up port resources.';
    } else if (name.includes('nginx')) {
      category = 'Network Service';
      importance = 'CRITICAL';
      safety = 'DANGEROUS_TO_KILL';
      reasoning = 'Critical operating system or core service. Terminating this process will cause system instability or disconnect network bindings.';
    } else if (name.includes('anydesk')) {
      category = 'Remote Access';
      importance = 'DEVELOPMENT';
      safety = 'SAFE_TO_KILL';
      reasoning = 'Desktop remote control sharing node (e.g. AnyDesk, TeamViewer). Use caution as this will close any active remote control sessions.';
    } else if (name.includes('chrome')) {
      category = 'Web Browser';
      importance = 'DEVELOPMENT';
      safety = 'SAFE_TO_KILL';
      reasoning = 'Local web browser socket connection helper thread (e.g. Chrome, Firefox). Safe to terminate.';
    }

    return {
      category,
      importance,
      safety,
      reasoning
    };
  };

  (window as any).__TAURI_INTERNALS__ = {
    ipc: async (message: any) => {
      console.log('Mock IPC called:', message);
      if (message.cmd === 'get_active_ports') {
        return mockPorts;
      }
      if (message.cmd === 'analyze_port_local') {
        return mockAnalyze(message.port, message.processName);
      }
      return {};
    },
    invoke: async (cmd: string, args: any) => {
      console.log('Mock Invoke called:', cmd, args);
      if (cmd === 'get_active_ports') {
        return mockPorts;
      }
      if (cmd === 'analyze_port_local') {
        return mockAnalyze(args.port, args.processName);
      }
      return {};
    },
    metadata: {},
    plugins: {},
    transformCallback: (callback: any) => callback,
  };
}
export {};
