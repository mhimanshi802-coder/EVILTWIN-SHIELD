// controllers/scanController.js
// WiFi scanning endpoints — real simulation engine with Socket.io events

const { performScan, generateAttackSimulation } = require('../services/wifiScanner');
const store = require('../services/memoryStore');

// @desc    Perform WiFi scan
// @route   GET /api/scan
// @access  Private (or public with optionalAuth)
exports.scan = async (req, res) => {
  try {
    const simulationMode = req.query.simulation === 'true';
    const result = performScan({ simulationMode });

    // Store scan in history
    const scanRecord = {
      _id: `scan_${Date.now()}`,
      scanId: result.scanId,
      userId: req.user ? req.user._id : 'anonymous',
      networks: result.networks,
      stats: result.stats,
      scannedAt: result.scannedAt,
    };
    store.addScan(scanRecord);

    // Update user stats
    if (req.user) {
      const user = store.findUser({ _id: req.user._id || req.user.id });
      if (user) user.totalScans = (user.totalScans || 0) + 1;
    }

    // Auto-log new HIGH/CRITICAL threats
    result.networks
      .filter(n => ['HIGH', 'CRITICAL'].includes(n.riskLevel) && (n.isRogue || n.isDuplicate))
      .forEach(net => {
        const attackType = net.isDuplicate ? 'evil_twin' : net.riskReasons.some(r => r.includes('signal')) ? 'signal_anomaly' : 'rogue_ap';
        store.addThreatLog({
          _id: `tl_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`,
          ssid: net.ssid,
          bssid: net.bssid,
          attackType,
          riskScore: net.riskScore,
          riskLevel: net.riskLevel,
          reasons: net.riskReasons,
          status: 'OPEN',
          source: 'auto_scan',
          createdAt: new Date(),
        });
      });

    // Emit Socket.io events if io is attached to app
    const io = req.app.get('io');
    if (io) {
      io.emit('scan-update', {
        type: 'scan-update',
        scanId: result.scanId,
        stats: result.stats,
        timestamp: result.scannedAt,
      });

      // Emit individual threat alerts
      result.networks
        .filter(n => ['HIGH', 'CRITICAL'].includes(n.riskLevel))
        .forEach(net => {
          io.emit('new-threat', {
            type: 'new-threat',
            ssid: net.ssid,
            bssid: net.bssid,
            riskLevel: net.riskLevel,
            riskScore: net.riskScore,
            reasons: net.riskReasons,
            timestamp: new Date(),
          });
        });
    }

    res.json({
      success: true,
      scanId: result.scanId,
      scannedAt: result.scannedAt,
      stats: result.stats,
      networks: result.networks,
    });
  } catch (err) {
    console.error('Scan error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
};

// @desc    Attack simulation mode
// @route   POST /api/scan/simulate
// @access  Private
exports.simulate = async (req, res) => {
  try {
    const result = generateAttackSimulation();
    const scanRecord = {
      _id: `sim_${Date.now()}`,
      scanId: result.scanId,
      userId: req.user ? req.user._id : 'anonymous',
      networks: result.networks,
      stats: result.stats,
      isSimulation: true,
      scannedAt: result.scannedAt,
    };
    store.addScan(scanRecord);

    const io = req.app.get('io');
    if (io) {
      // Stream simulation events with delays
      result.simulationEvents.forEach(event => {
        setTimeout(() => {
          io.emit('alert', {
            type: 'alert',
            event: event.event,
            message: event.message,
            severity: event.severity,
            timestamp: new Date(),
          });
        }, event.time);
      });

      io.emit('scan-update', { type: 'scan-update', stats: result.stats, isSimulation: true });
    }

    res.json({
      success: true,
      isSimulation: true,
      scanId: result.scanId,
      stats: result.stats,
      networks: result.networks,
      simulationEvents: result.simulationEvents,
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

// @desc    Get scan history
// @route   GET /api/scan/history
// @access  Private
exports.history = async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 20, 100);
  const history = store.scanHistory.slice(0, limit).map(s => ({
    scanId: s.scanId,
    scannedAt: s.scannedAt,
    stats: s.stats,
    isSimulation: s.isSimulation || false,
  }));
  res.json({ success: true, count: history.length, data: history });
};