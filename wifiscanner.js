// services/wifiScanner.js
// Core WiFi scanning simulation engine with realistic network generation
// and intelligent risk detection algorithm

const { v4: uuidv4 } = require('uuid');

// ─── Real-world SSID pools ────────────────────────────────────────────────────
const SSID_POOLS = {
  cafe:      ['Starbucks_WiFi', 'CafeNet_Guest', 'CoffeeHouse_Free', 'Cafe_Public', 'BrewCo_WiFi'],
  hotel:     ['Hotel_Guest', 'Marriott_WiFi', 'HiltonHonors', 'IHG_Connect', 'Holiday_Guest'],
  airport:   ['Airport_Free_WiFi', 'Terminal_WiFi', 'AirportLounge', 'FlyFree_Net', 'Gate_Connect'],
  isp:       ['xfinitywifi', 'ATT_WiFi', 'Spectrum_Free', 'BSNL_Public', 'Jio_Hotspot'],
  mall:      ['MallFree_WiFi', 'ShopConnect', 'Retail_Guest', 'CityMall_Net', 'PlazaWiFi'],
  generic:   ['FreePublicWifi', 'OpenNet', 'Public_WiFi', 'Guest_Network', 'Internet_Free'],
  home:      ['HomeNet_5G', 'MyWiFi', 'Netgear_Home', 'DLINK_2G', 'HomeRouter'],
  office:    ['OfficeNet_Corp', 'BizConnect', 'Enterprise_Net', 'Corp_Secure', 'WorkWiFi'],
};

// ─── Known legitimate vendors ─────────────────────────────────────────────────
const LEGIT_VENDORS = ['Cisco Systems', 'Aruba Networks', 'Ubiquiti', 'TP-Link', 'Netgear',
  'Ruckus Wireless', 'Juniper Networks', 'Extreme Networks', 'D-Link', 'ASUS'];

// ─── Vendors used by attackers (cheap, high-power adapters) ──────────────────
const ROGUE_VENDORS = ['Alfa Networks', 'Panda Wireless', 'Realtek RTL8812', 'Ralink Tech',
  'Unknown', 'Generic USB WiFi', 'MediaTek MT7612'];

// ─── OUI prefixes for MAC generation ─────────────────────────────────────────
const LEGIT_OUI = ['00:1A:2B', '00:23:CD', 'A4:C3:F0', '5C:AA:FD', 'B8:27:EB', '68:7F:74'];
const ROGUE_OUI  = ['AA:BB:CC', 'DE:AD:BE', 'CA:FE:BA', 'BA:DC:0D', 'EV:IL:00', 'FA:KE:AP'];

// ─── Encryption distribution ──────────────────────────────────────────────────
const ENCRYPTIONS = [
  { type: 'WPA3',            weight: 10 },
  { type: 'WPA2',            weight: 45 },
  { type: 'WPA2-Enterprise', weight: 10 },
  { type: 'WPA',             weight: 10 },
  { type: 'Open',            weight: 15 },
  { type: 'WEP',             weight: 10 },
];

// ─── Helpers ──────────────────────────────────────────────────────────────────
function randomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function randomElement(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function weightedRandom(items) {
  const total = items.reduce((s, i) => s + i.weight, 0);
  let r = Math.random() * total;
  for (const item of items) {
    r -= item.weight;
    if (r <= 0) return item.type;
  }
  return items[items.length - 1].type;
}

function generateMAC(oui) {
  const base = oui || randomElement(LEGIT_OUI);
  const rand = Array.from({ length: 3 }, () =>
    randomInt(0, 255).toString(16).padStart(2, '0').toUpperCase()
  );
  return `${base}:${rand.join(':')}`;
}

function getAllSSIDs() {
  return Object.values(SSID_POOLS).flat();
}

// ─── Core risk scoring algorithm ──────────────────────────────────────────────
function calculateRisk(network, allNetworks) {
  let score = 0;
  const reasons = [];

  // 1. Duplicate SSID with different BSSID → classic Evil Twin
  const duplicates = allNetworks.filter(
    n => n.ssid === network.ssid && n.bssid !== network.bssid
  );
  if (duplicates.length > 0) {
    score += 40;
    reasons.push(`Duplicate SSID detected (${duplicates.length} other AP${duplicates.length > 1 ? 's' : ''} share this name)`);
  }

  // 2. Open / no encryption
  if (network.encryption === 'Open') {
    score += 20;
    reasons.push('No encryption — traffic fully exposed to interception');
  }

  // 3. Weak legacy encryption
  if (network.encryption === 'WEP') {
    score += 15;
    reasons.push('WEP encryption is cryptographically broken since 2001');
  }

  // 4. Abnormally strong signal (boosted rogue AP)
  if (network.signal > -45) {
    score += 15;
    reasons.push(`Unusually strong signal (${network.signal} dBm) — possible boosted rogue AP`);
  }

  // 5. Unknown / rogue vendor
  const knownVendors = [...LEGIT_VENDORS.map(v => v.toLowerCase())];
  const vendorKnown = knownVendors.some(v => network.vendor.toLowerCase().includes(v.split(' ')[0].toLowerCase()));
  if (!vendorKnown || network.vendor === 'Unknown') {
    score += 25;
    reasons.push(`Unrecognized hardware vendor: "${network.vendor}"`);
  }

  // 6. Known SSID but open/weak encryption (captive portal trap)
  const knownSSIDs = getAllSSIDs();
  const isKnownSSID = knownSSIDs.some(s => network.ssid.toLowerCase().includes(s.split('_')[0].toLowerCase()));
  if (isKnownSSID && ['Open', 'WEP', 'WPA'].includes(network.encryption)) {
    score += 15;
    reasons.push(`Known commercial SSID "${network.ssid}" using weak/no encryption — likely captive portal trap`);
  }

  // 7. Rogue OUI prefix in BSSID
  const bssidOUI = network.bssid.substring(0, 8).toUpperCase();
  const isRogueOUI = ROGUE_OUI.some(o => bssidOUI.startsWith(o.substring(0, 5)));
  if (isRogueOUI) {
    score += 10;
    reasons.push('BSSID OUI belongs to known attacker hardware (Alfa/Panda class adapter)');
  }

  const capped = Math.min(score, 100);
  let level = 'LOW';
  if (capped >= 80) level = 'CRITICAL';
  else if (capped >= 60) level = 'HIGH';
  else if (capped >= 35) level = 'MEDIUM';

  return { riskScore: capped, riskLevel: level, riskReasons: reasons };
}

// ─── Generate a single realistic network ─────────────────────────────────────
function generateNetwork(options = {}) {
  const isRogue = options.isRogue || false;
  const ssidPool = Object.values(SSID_POOLS).flat();
  const ssid = options.ssid || randomElement(ssidPool);
  const vendor = isRogue ? randomElement(ROGUE_VENDORS) : randomElement(LEGIT_VENDORS);
  const oui = isRogue ? randomElement(ROGUE_OUI) : randomElement(LEGIT_OUI);
  const bssid = options.bssid || generateMAC(oui);
  const signal = isRogue ? randomInt(-45, -30) : randomInt(-90, -50);
  const channel = randomElement([1, 6, 11, 36, 40, 44, 48]);
  const frequency = channel > 14 ? '5GHz' : '2.4GHz';
  const encryption = isRogue
    ? weightedRandom([{ type: 'Open', weight: 50 }, { type: 'WEP', weight: 20 }, { type: 'WPA', weight: 30 }])
    : weightedRandom(ENCRYPTIONS);

  return { ssid, bssid, signal, channel, frequency, encryption, vendor, isDuplicate: false, isRogue };
}

// ─── Main scan function ───────────────────────────────────────────────────────
function performScan(options = {}) {
  const {
    includeAttacks = true,
    networkCount = randomInt(12, 22),
    simulationMode = false,
  } = options;

  const networks = [];
  const usedSSIDs = new Set();
  const usedBSSIDs = new Set();

  // Generate base legitimate networks
  for (let i = 0; i < networkCount; i++) {
    let net;
    let attempts = 0;
    do {
      net = generateNetwork({ isRogue: false });
      attempts++;
    } while (usedBSSIDs.has(net.bssid) && attempts < 10);

    usedBSSIDs.add(net.bssid);
    usedSSIDs.add(net.ssid);
    networks.push(net);
  }

  const injectedThreats = [];

  if (includeAttacks) {
    // ── Inject Evil Twin (duplicate SSID, rogue vendor, boosted signal) ──────
    const evilTwinCount = simulationMode ? randomInt(3, 5) : randomInt(1, 3);
    const legitNets = networks.filter(n => usedSSIDs.has(n.ssid));
    for (let i = 0; i < evilTwinCount; i++) {
      const target = randomElement(legitNets);
      const twin = generateNetwork({ isRogue: true, ssid: target.ssid });
      twin.isDuplicate = true;
      target.isDuplicate = true;
      usedBSSIDs.add(twin.bssid);
      networks.push(twin);
      injectedThreats.push({ type: 'evil_twin', ssid: twin.ssid });
    }

    // ── Inject Rogue APs (generic honeypot names) ─────────────────────────
    const rogueCount = simulationMode ? randomInt(2, 4) : randomInt(1, 2);
    const rogueSSIDs = ['FreePublicWifi', 'OpenNet', 'Free_Internet', 'Public_WiFi_Free', 'GuestAccess'];
    for (let i = 0; i < rogueCount; i++) {
      const rogue = generateNetwork({ isRogue: true, ssid: randomElement(rogueSSIDs) });
      rogue.encryption = 'Open';
      networks.push(rogue);
      injectedThreats.push({ type: 'rogue_ap', ssid: rogue.ssid });
    }

    // ── Inject Signal Spike (legitimate SSID, unusual signal strength) ─────
    if (simulationMode || Math.random() > 0.4) {
      const spikeTarget = randomElement(networks.filter(n => !n.isRogue));
      if (spikeTarget) {
        const spike = { ...spikeTarget };
        spike.signal = randomInt(-38, -30);
        spike.bssid = generateMAC(randomElement(ROGUE_OUI));
        spike.vendor = randomElement(ROGUE_VENDORS);
        spike.isRogue = true;
        networks.push(spike);
        injectedThreats.push({ type: 'signal_anomaly', ssid: spike.ssid });
      }
    }
  }

  // Calculate risk for all networks
  const scored = networks.map(net => {
    const { riskScore, riskLevel, riskReasons } = calculateRisk(net, networks);
    return { ...net, riskScore, riskLevel, riskReasons, scanId: uuidv4() };
  });

  // Sort by risk score descending
  scored.sort((a, b) => b.riskScore - a.riskScore);

  const stats = {
    total: scored.length,
    critical: scored.filter(n => n.riskLevel === 'CRITICAL').length,
    high:     scored.filter(n => n.riskLevel === 'HIGH').length,
    medium:   scored.filter(n => n.riskLevel === 'MEDIUM').length,
    low:      scored.filter(n => n.riskLevel === 'LOW').length,
    threats:  scored.filter(n => n.isRogue || n.isDuplicate).length,
    injectedThreats,
  };

  return { networks: scored, stats, scanId: uuidv4(), scannedAt: new Date() };
}

// ─── Generate realistic attack simulation ────────────────────────────────────
function generateAttackSimulation() {
  const result = performScan({ includeAttacks: true, simulationMode: true, networkCount: 15 });

  // Add dramatic deauth simulation events
  result.simulationEvents = [
    { event: 'DEAUTH_FLOOD',    time: 0,    message: 'Deauthentication packet flood detected on channel 6', severity: 'CRITICAL' },
    { event: 'EVIL_TWIN_UP',    time: 1500, message: 'Evil Twin AP broadcasting — same SSID, different BSSID', severity: 'HIGH' },
    { event: 'VICTIM_CONNECT',  time: 3000, message: 'Device 00:AA:BB:CC:DD:EE connected to rogue AP', severity: 'HIGH' },
    { event: 'MITM_ACTIVE',     time: 4500, message: 'MITM traffic interception active on rogue AP', severity: 'CRITICAL' },
    { event: 'CAPTIVE_PORTAL',  time: 6000, message: 'Captive portal served to victim — credential harvest attempt', severity: 'CRITICAL' },
    { event: 'SSL_STRIP',       time: 7500, message: 'SSL stripping detected — HTTPS downgraded to HTTP', severity: 'CRITICAL' },
  ];

  return result;
}

module.exports = { performScan, generateAttackSimulation, calculateRisk, generateNetwork };