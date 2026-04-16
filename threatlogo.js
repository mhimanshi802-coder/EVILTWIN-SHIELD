// models/ThreatLog.js
// Persistent threat event logs

const mongoose = require('mongoose');

const ThreatLogSchema = new mongoose.Schema({
  ssid: { type: String, required: true },
  bssid: { type: String, required: true },
  attackType: {
    type: String,
    enum: [
      'evil_twin',
      'rogue_ap',
      'deauth',
      'signal_anomaly',
      'captive_portal',
      'vendor_spoof',
      'other',
    ],
    required: true,
  },
  riskScore: { type: Number, min: 0, max: 100 },
  riskLevel: {
    type: String,
    enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
    default: 'LOW',
  },
  reasons: [{ type: String }],
  details: { type: String },
  status: {
    type: String,
    enum: ['OPEN', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'],
    default: 'OPEN',
  },
  source: {
    type: String,
    enum: ['auto_scan', 'user_report', 'simulation'],
    default: 'auto_scan',
  },
  resolvedAt: { type: Date },
  createdAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model('ThreatLog', ThreatLogSchema);