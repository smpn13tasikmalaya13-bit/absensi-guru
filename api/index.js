const express = require("express");
const app = express();

// Middleware untuk JSON
app.use(express.json());

// Contoh route utama
app.get("/", (req, res) => {
  res.send("🚀 API Absensi Guru berjalan dengan baik!");
});

// Bisa tambah route lain
app.get("/ping", (req, res) => {
  res.json({ message: "pong" });
});

// Export app untuk serverless function
module.exports = app;

