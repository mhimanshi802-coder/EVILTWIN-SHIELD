// server.js
// EvilTwin Shield — Main Server Entry Point
// Node.js + Express + Socket.io

require('dotenv').config();

const express   = require('express');
const http      = require('http');
const { Server } = require('socket.io');
const cors      = require('cors');
const rateLimit = require('express-rate-limit');
const path      = require('path');
const connectDB = require('./config/database');
const routes    = require('./routes/index');

const app    = express();
const server = http.createServer(app);

// ─── Socket.io Setup ──────────────────────────────────────────────────────────
const io = new Server(server, {
  cors: {
    origin: process.env.FRONTEND_URL || '*',
    methods: ['GET', 'POST'],
  },
});

// Attach io to app so controllers can emit events
app.set('io', io);

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true }));

// Serve frontend static files
app.use(express.static(path.join(__dirname, '../frontend')));

// Rate limiting — 200 requests per 15 minutes per IP
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: { success: false, error: 'Too many requests, please try again later' },
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api/', limiter);

// ─── API Routes ───────────────────────────────────────────────────────────────
app.use('/api', routes);

// ─── Fallback: serve frontend for all non-API routes ─────────────────────────
app.get('*', (req, res) => {
  if (!req.path.startsWith('/api')) {
    res.sendFile(path.join(__dirname, '../frontend/index.html'));
  }
});

// ─── Socket.io Event Handlers ─────────────────────────────────────────────────
let connectedClients = 0;

io.on('connection', socket => {
  connectedClients++;
  console.log(`🔌 Client connected [${socket.id}] — Total: ${connectedClients}`);

  // Send welcome / system status
  socket.emit('connected', {
    message: 'Connected to EvilTwin Shield real-time feed',
    timestamp: new Date(),
    clientId: socket.id,
  });

  // Handle client requesting a scan via socket
  socket.on('request-scan', async (data) => {
    try {
      const { performScan } = require('./services/wifiScanner');
      const result = performScan({ simulationMode: data?.simulation || false });
      socket.emit('scan-update', { type: 'scan-update', ...result });
      result.networks
        .filter(n => ['HIGH', 'CRITICAL'].includes(n.riskLevel))
        .forEach(net => socket.emit('new-threat', { type: 'new-threat', ...net }));
    } catch (err) {
      socket.emit('error', { message: err.message });
    }
  });

  socket.on('disconnect', () => {
    connectedClients--;
    console.log(`🔌 Client disconnected [${socket.id}] — Total: ${connectedClients}`);
  });
});

// ─── Periodic background simulation (every 45 seconds) ───────────────────────
let bgScanCount = 0;
setInterval(() => {
  if (connectedClients === 0) return; // Don't scan if no one is listening
  bgScanCount++;
  const { performScan } = require('./services/wifiScanner');
  const result = performScan({ includeAttacks: bgScanCount % 3 === 0 });

  io.emit('scan-update', {
    type: 'background-scan',
    stats: result.stats,
    timestamp: result.scannedAt,
    scanNumber: bgScanCount,
  });

  const highThreats = result.networks.filter(n => ['HIGH', 'CRITICAL'].includes(n.riskLevel));
  if (highThreats.length > 0) {
    io.emit('alert', {
      type: 'alert',
      event: 'BACKGROUND_THREAT',
      message: `Background scan detected ${highThreats.length} high-risk network(s)`,
      severity: highThreats.some(n => n.riskLevel === 'CRITICAL') ? 'CRITICAL' : 'HIGH',
      threats: highThreats.slice(0, 3).map(n => ({ ssid: n.ssid, riskLevel: n.riskLevel })),
      timestamp: new Date(),
    });
  }
}, 45000);

// ─── Start Server ─────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3001;

const start = async () => {
  await connectDB(); // Connect to MongoDB (non-blocking — uses memory store if unavailable)
  server.listen(PORT, () => {
    console.log('\n╔════════════════════════════════════════╗');
    console.log(`║   EvilTwin Shield API — Port ${PORT}      ║`);
    console.log('╚════════════════════════════════════════╝');
    console.log(`🚀 API:       http://localhost:${PORT}/api`);
    console.log(`🌐 Frontend:  http://localhost:${PORT}`);
    console.log(`📡 Socket.io: ws://localhost:${PORT}`);
    console.log(`🔑 Admin:     admin@eviltwin.local / admin123\n`);
  });
};

start();

module.exports = { app, server, io };