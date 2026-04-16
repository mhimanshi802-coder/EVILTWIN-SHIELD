// models/Report.js
// User-submitted suspicious network reports

const mongoose = require('mongoose');

const ReportSchema = new mongoose.Schema({
  reportId: { type: String, unique: true },
  ssid: { type: String, required: true, maxlength: 64 },
  bssid: { type: String, default: 'Unknown' },
  location: { type: String, maxlength: 200, default: 'Unknown' },
  latitude: { type: Number },
  longitude: { type: Number },
  threatType: {
    type: String,
    required: true,
    enum: [
      'Evil Twin',
      'Rogue AP',
      'Captive Portal Phishing',
      'Deauth Attack',
      'Signal Anomaly',
      'Other',
    ],
  },
  riskLevel: {
    type: String,
    required: true,
    enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
  },
  details: { type: String, maxlength: 2000 },
  status: {
    type: String,
    enum: ['OPEN', 'REVIEWING', 'CONFIRMED', 'DISMISSED'],
    default: 'OPEN',
  },
  submittedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  submittedAt: { type: Date, default: Date.now },
  resolvedAt: { type: Date },
});

// Auto-generate report ID
ReportSchema.pre('save', function (next) {
  if (!this.reportId) {
    this.reportId = 'RPT-' + Date.now().toString(36).toUpperCase();
  }
  next();
});

module.exports = mongoose.model('Report', ReportSchema);