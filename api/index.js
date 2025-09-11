const express = require("express");
const app = express();

// Middleware
app.use(express.json());

// Routes
app.get("/", (req, res) => {
  res.send("🚀 API Absensi Guru berjalan di Vercel!");
});

// Untuk testing
app.get("/ping", (req, res) => {
  res.json({ message: "pong" });
});

// Jangan pakai app.listen(), tapi export handler:
module.exports = app;
