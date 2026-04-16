// services/memoryStore.js
// In-memory data store — used when MongoDB is not connected
// Keeps the API fully functional without a database

const store = {
  users: [
    {
      _id: 'admin001',
      username: 'admin',
      email: 'admin@eviltwin.local',
      // bcrypt hash of "admin123"
      password: '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewfnkDTlbh2Z6Hxq',
      role: 'admin',
      totalScans: 42,
      totalReports: 8,
      createdAt: new Date(Date.now() - 86400000 * 7),
    },
    {
      _id: 'user001',
      username: 'analyst',
      email: 'analyst@eviltwin.local',
      password: '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewfnkDTlbh2Z6Hxq',
      role: 'user',
      totalScans: 12,
      totalReports: 3,
      createdAt: new Date(Date.now() - 86400000 * 3),
    },
  ],

  scanHistory: [],

  reports: [
    {
      _id: 'r001',
      reportId: 'RPT-INIT001',
      ssid: 'Airport_Free_WiFi',
      bssid: 'FF:EE:DD:CC:BB:AA',
      location: 'T3 International Airport',
      latitude: 28.5665,
      longitude: 77.1031,
      threatType: 'Evil Twin',
      riskLevel: 'HIGH',
      details: 'Open network with captive portal requesting passport/boarding pass info',
      status: 'OPEN',
      submittedAt: new Date(Date.now() - 3600000 * 2),
    },
    {
      _id: 'r002',
      reportId: 'RPT-INIT002',
      ssid: 'Starbucks_WiFi',
      bssid: 'AA:BB:CC:11:22:33',
      location: 'Connaught Place, New Delhi',
      latitude: 28.6315,
      longitude: 77.2167,
      threatType: 'Deauth Attack',
      riskLevel: 'CRITICAL',
      details: 'Repeated client disconnections + suspicious duplicate SSID detected',
      status: 'REVIEWING',
      submittedAt: new Date(Date.now() - 3600000 * 5),
    },
    {
      _id: 'r003',
      reportId: 'RPT-INIT003',
      ssid: 'MallFree_WiFi',
      bssid: '99:00:AA:BB:CC:DD',
      location: 'DLF Mall, Gurugram',
      latitude: 28.4954,
      longitude: 77.0893,
      threatType: 'Captive Portal Phishing',
      riskLevel: 'MEDIUM',
      details: 'Unexpected login page asking for credit card info',
      status: 'OPEN',
      submittedAt: new Date(Date.now() - 3600000 * 12),
    },
  ],

  threatLogs: [
    { _id: 'tl001', ssid: 'Starbucks_WiFi',    bssid: 'AA:BB:CC:11:22:33', attackType: 'evil_twin',     riskScore: 95, riskLevel: 'CRITICAL', reasons: ['Duplicate SSID', 'Boosted signal', 'Rogue vendor'], status: 'OPEN', source: 'auto_scan', createdAt: new Date(Date.now() - 3600000 * 1) },
    { _id: 'tl002', ssid: 'Airport_Free_WiFi', bssid: 'FF:EE:DD:CC:BB:AA', attackType: 'rogue_ap',      riskScore: 88, riskLevel: 'HIGH',     reasons: ['Open encryption', 'Unknown vendor', 'Known SSID + weak auth'], status: 'OPEN', source: 'auto_scan', createdAt: new Date(Date.now() - 3600000 * 2) },
    { _id: 'tl003', ssid: 'CafeNet',           bssid: '77:88:99:00:AA:BB', attackType: 'signal_anomaly', riskScore: 55, riskLevel: 'MEDIUM',   reasons: ['Signal spike at -38 dBm'], status: 'INVESTIGATING', source: 'auto_scan', createdAt: new Date(Date.now() - 3600000 * 3) },
    { _id: 'tl004', ssid: 'Hotel_Guest',        bssid: 'BB:44:CC:55:DD:66', attackType: 'evil_twin',     riskScore: 75, riskLevel: 'HIGH',     reasons: ['Duplicate SSID', 'Rogue vendor'], status: 'OPEN', source: 'auto_scan', createdAt: new Date(Date.now() - 3600000 * 6) },
    { _id: 'tl005', ssid: 'FreePublicWifi',     bssid: 'EE:FF:00:11:22:33', attackType: 'rogue_ap',      riskScore: 82, riskLevel: 'HIGH',     reasons: ['Open encryption', 'Unknown vendor'], status: 'RESOLVED', source: 'user_report', createdAt: new Date(Date.now() - 3600000 * 24) },
  ],
};

// Generic CRUD helpers
store.findUser       = (query) => store.users.find(u => Object.entries(query).every(([k,v]) => u[k] === v));
store.addUser        = (user)  => { store.users.push(user); return user; };
store.addReport      = (r)     => { store.reports.push(r); return r; };
store.addThreatLog   = (t)     => { store.threatLogs.push(t); return t; };
store.addScan        = (s)     => { store.scanHistory.unshift(s); if (store.scanHistory.length > 200) store.scanHistory.pop(); return s; };

module.exports = store;