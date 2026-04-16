// middleware/auth.js
// JWT authentication and role-based access control middleware

const jwt = require('jsonwebtoken');
const store = require('../services/memoryStore');

// Verify JWT token
const protect = (req, res, next) => {
  let token;

  // Check Authorization header
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
    token = req.headers.authorization.split(' ')[1];
  }

  if (!token) {
    return res.status(401).json({ success: false, error: 'Not authorized — token required' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    // Attach user to request
    req.user = store.findUser({ _id: decoded.id }) || { _id: decoded.id, role: decoded.role, username: decoded.username };
    next();
  } catch (err) {
    return res.status(401).json({ success: false, error: 'Invalid or expired token' });
  }
};

// Restrict to specific roles
const authorize = (...roles) => (req, res, next) => {
  if (!roles.includes(req.user.role)) {
    return res.status(403).json({
      success: false,
      error: `Role '${req.user.role}' is not authorized for this action`,
    });
  }
  next();
};

// Optional auth — doesn't block, just attaches user if token present
const optionalAuth = (req, res, next) => {
  let token;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
    token = req.headers.authorization.split(' ')[1];
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = store.findUser({ _id: decoded.id }) || decoded;
    } catch (_) {}
  }
  next();
};

module.exports = { protect, authorize, optionalAuth };