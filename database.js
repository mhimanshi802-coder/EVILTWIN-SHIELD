// config/database.js
// MongoDB connection configuration

const mongoose = require('mongoose');

const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGO_URI, {
      serverSelectionTimeoutMS: 5000,
    });
    console.log(`✅ MongoDB Connected: ${conn.connection.host}`);
    return conn;
  } catch (error) {
    console.error(`❌ MongoDB Connection Error: ${error.message}`);
    // In development, continue with in-memory simulation if MongoDB is unavailable
    console.log('⚠️  Running in simulation mode (no database)');
    return null;
  }
};

module.exports = connectDB;