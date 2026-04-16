// controllers/authController.js
// User registration, login, and profile management

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const store = require('../services/memoryStore');

// Generate JWT
const signToken = (user) =>
  jwt.sign(
    { id: user._id, role: user.role, username: user.username },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRE || '7d' }
  );

// @desc    Register new user
// @route   POST /api/auth/register
// @access  Public
exports.register = async (req, res) => {
  try {
    const { username, email, password, role } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ success: false, error: 'Username, email, and password are required' });
    }

    if (store.findUser({ email })) {
      return res.status(400).json({ success: false, error: 'Email already registered' });
    }

    if (store.findUser({ username })) {
      return res.status(400).json({ success: false, error: 'Username already taken' });
    }

    const salt = await bcrypt.genSalt(12);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = {
      _id: `user_${Date.now()}`,
      username: username.trim(),
      email: email.toLowerCase().trim(),
      password: hashedPassword,
      role: role === 'admin' ? 'user' : (role || 'user'), // can't self-assign admin
      totalScans: 0,
      totalReports: 0,
      createdAt: new Date(),
    };

    store.addUser(newUser);
    const token = signToken(newUser);

    res.status(201).json({
      success: true,
      token,
      user: {
        id: newUser._id,
        username: newUser.username,
        email: newUser.email,
        role: newUser.role,
      },
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

// @desc    Login user
// @route   POST /api/auth/login
// @access  Public
exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ success: false, error: 'Email and password are required' });
    }

    const user = store.findUser({ email: email.toLowerCase().trim() });
    if (!user) {
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }

    user.lastLogin = new Date();
    const token = signToken(user);

    res.json({
      success: true,
      token,
      user: { id: user._id, username: user.username, email: user.email, role: user.role },
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

// @desc    Get current user profile
// @route   GET /api/auth/me
// @access  Private
exports.getMe = async (req, res) => {
  const user = store.findUser({ _id: req.user._id || req.user.id });
  if (!user) return res.status(404).json({ success: false, error: 'User not found' });

  res.json({
    success: true,
    user: {
      id: user._id,
      username: user.username,
      email: user.email,
      role: user.role,
      totalScans: user.totalScans,
      totalReports: user.totalReports,
      createdAt: user.createdAt,
    },
  });
};