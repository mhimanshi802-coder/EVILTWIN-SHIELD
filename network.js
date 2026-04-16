// models/Network.js
// WiFi network model for storing scan results

const mongoose = require('mongoose');

const NetworkSchema = new mongoose.Schema({
  scanId: {
    type: String,
    required: true,
    index: true,
  },
  ssid: {
    type: String,
    required: true,
    maxlength: 64,
  },
  bssid: {
    type: String,
    required: true,
    match: [/^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/, 'Invalid BSSID format'],
  },
  signal: {
    type: Number,
    min: -120,
    max: 0,
  },
  channel: {
    type: Number,
    min: 1,
    max: 165,
  },
  encryption: {
    type: String,
    enum: ['Open', 'WEP', 'WPA', 'WPA2', 'WPA3', 'WPA2-Enterprise'],
    default: 'WPA2',
  },
  vendor: { type: String, default: 'Unknown' },
  frequency: { type: String, default: '2.4GHz' },
  isDuplicate: { type: Boolean, default: false },
  isRogue: { type: Boolean, default: false },
  riskScore: { type: Number, default: 0, min: 0, max: 100 },
  riskLevel: {
    type: String,
    enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
    default: 'LOW',
  },
  riskReasons: [{ type: String }],
  scannedAt: { type: Date, default: Date.now },
  scannedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
});

module.exports = mongoose.model('Network', NetworkSchema);