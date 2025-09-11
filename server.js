require('dotenv').config();

const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const qrcode = require('qrcode');
const { Parser } = require('json2csv');
const jsPDF = require('jspdf');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// Supabase client dengan konfigurasi header yang benar
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY,
  {
    headers: {
      apikey: process.env.SUPABASE_KEY,
      Authorization: `Bearer ${process.env.SUPABASE_KEY}`
    }
  }
);

// Debug: Cek apakah environment variables terbaca
console.log('=== Environment Variables ===');
console.log('SUPABASE_URL:', process.env.SUPABASE_URL);
console.log('SUPABASE_KEY:', process.env.SUPABASE_KEY ? '***' : 'NOT FOUND');
console.log('JWT_SECRET:', process.env.JWT_SECRET ? '***' : 'NOT FOUND');
console.log('PORT:', process.env.PORT);
console.log('============================');

// Middleware untuk verifikasi token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.sendStatus(401);
  
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Endpoint untuk mendapatkan data user berdasarkan token
app.get('/auth/me', authenticateToken, async (req, res) => {
  try {
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('id', req.user.id)
      .single();
    
    if (error || !user) {
      return res.status(404).json({ message: 'User tidak ditemukan' });
    }
    
    // Get data guru jika role guru
    let guruData = null;
    if (user.role === 'guru') {
      const { data: guru } = await supabase
        .from('guru')
        .select('*')
        .eq('user_id', user.id)
        .single();
      guruData = guru;
    }
    
    res.json({
      user: {
        ...user,
        guru: guruData
      }
    });
  } catch (error) {
    console.error('Get me error:', error);
    res.status(500).json({ message: 'Terjadi kesalahan server' });
  }
});

// Endpoint autentikasi login
app.post('/auth/login', async (req, res) => {
  const { username, password, deviceId } = req.body;
  
  try {
    // Cari user di database
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('username', username)
      .single();
    
    if (error || !user) {
      return res.status(401).json({ message: 'Username atau password salah' });
    }
    
    // Verifikasi password
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ message: 'Username atau password salah' });
    }
    
    // Untuk role guru, cek device binding
    if (user.role === 'guru' && user.device_id && user.device_id !== deviceId) {
      return res.status(403).json({ 
        message: 'Akun ini sudah terikat dengan device lain. Hubungi admin untuk reset device.' 
      });
    }
    
    // Update device_id jika belum ada
    if (user.role === 'guru' && !user.device_id) {
      await supabase
        .from('users')
        .update({ device_id: deviceId })
        .eq('id', user.id);
    }
    
    // Buat token JWT
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    // Get data guru jika role guru
    let guruData = null;
    if (user.role === 'guru') {
      const { data: guru } = await supabase
        .from('guru')
        .select('*')
        .eq('user_id', user.id)
        .single();
      guruData = guru;
    }
    
    res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
        guru: guruData
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Terjadi kesalahan server' });
  }
});

// Endpoint Sign Up
app.post('/auth/signup', async (req, res) => {
  const { username, password, role, nama, nip, email, no_hp } = req.body;
  
  try {
    // Validasi input
    if (!username || !password || !role) {
      return res.status(400).json({ message: 'Username, password, dan role harus diisi' });
    }
    
    if (role === 'guru' && !nama) {
      return res.status(400).json({ message: 'Nama harus diisi untuk role guru' });
    }
    
    // Cek apakah username sudah ada
    const { data: existingUser, error: checkError } = await supabase
      .from('users')
      .select('*')
      .eq('username', username)
      .single();
    
    if (existingUser) {
      return res.status(409).json({ message: 'Username sudah digunakan' });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Buat user
    const { data: user, error: userError } = await supabase
      .from('users')
      .insert([{
        username,
        password: hashedPassword,
        role
      }])
      .single();
    
    if (userError) {
      throw userError;
    }
    
    // Jika role adalah guru, buat data guru
    if (role === 'guru') {
      const { data: guru, error: guruError } = await supabase
        .from('guru')
        .insert([{
          user_id: user.id,
          nama,
          nip,
          email,
          no_hp
        }])
        .single();
      
      if (guruError) {
        // Rollback user jika gagal membuat guru
        await supabase.from('users').delete().eq('id', user.id);
        throw guruError;
      }
      
      // Log audit
      await supabase
        .from('audit_log')
        .insert([{
          user_id: user.id,
          aksi: 'SIGNUP',
          target_id: guru.id,
          target_type: 'guru',
          detail: `Registrasi guru baru: ${nama}`
        }]);
      
      res.status(201).json({
        message: 'Registrasi guru berhasil',
        user: {
          id: user.id,
          username: user.username,
          role: user.role
        }
      });
    } else {
      // Log audit untuk admin
      await supabase
        .from('audit_log')
        .insert([{
          user_id: user.id,
          aksi: 'SIGNUP',
          target_id: user.id,
          target_type: 'admin',
          detail: `Registrasi admin baru: ${username}`
        }]);
      
      res.status(201).json({
        message: 'Registrasi admin berhasil',
        user: {
          id: user.id,
          username: user.username,
          role: user.role
        }
      });
    }
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ message: 'Terjadi kesalahan server' });
  }
});

// Endpoint untuk generate QR Code kelas
app.get('/kelas/qrcode/:kelasId', authenticateToken, async (req, res) => {
  const { kelasId } = req.params;
  
  try {
    // Cek kelas
    const { data: kelas, error } = await supabase
      .from('kelas')
      .select('*')
      .eq('id', kelasId)
      .single();
    
    if (error || !kelas) {
      return res.status(404).json({ message: 'Kelas tidak ditemukan' });
    }
    
    // Generate QR Code
    const qrCodeDataURL = await qrcode.toDataURL(kelas.qr_token);
    
    res.json({
      kelas,
      qrCodeDataURL
    });
  } catch (error) {
    console.error('Generate QR Code error:', error);
    res.status(500).json({ message: 'Terjadi kesalahan server' });
  }
});

// Endpoint untuk scan absensi
app.post('/absen/scan', authenticateToken, async (req, res) => {
  const { qrToken, jamKe } = req.body;
  const guruId = req.user.guru.id;
  
  try {
    // Cek kelas berdasarkan qr_token
    const { data: kelas, error: kelasError } = await supabase
      .from('kelas')
      .select('*')
      .eq('qr_token', qrToken)
      .single();
    
    if (kelasError || !kelas) {
      return res.status(404).json({ message: 'QR Code tidak valid' });
    }
    
    // Cek jadwal aktif
    const now = new Date();
    const hari = now.toLocaleDateString('id-ID', { weekday: 'long' });
    const currentTime = now.toTimeString().slice(0, 5);
    
    const { data: jadwal, error: jadwalError } = await supabase
      .from('jadwal')
      .select('*')
      .eq('guru_id', guruId)
      .eq('kelas_id', kelas.id)
      .eq('hari', hari)
      .eq('jam_ke', jamKe)
      .single();
    
    if (jadwalError || !jadwal) {
      return res.status(404).json({ 
        message: 'Jadwal pelajaran tidak ditemukan untuk jam ini' 
      });
    }
    
    // Cek apakah waktu sekarang dalam rentang jadwal
    if (currentTime < jadwal.jam_mulai || currentTime > jadwal.jam_selesai) {
      return res.status(400).json({ 
        message: 'Absensi hanya bisa dilakukan pada jam pelajaran yang telah ditentukan' 
      });
    }
    
    // Cek double scan untuk jam pelajaran yang sama
    const today = now.toISOString().split('T')[0];
    const { data: existingAbsensi, error: absensiError } = await supabase
      .from('absensi')
      .select('*')
      .eq('guru_id', guruId)
      .eq('kelas_id', kelas.id)
      .eq('jam_ke', jamKe)
      .gte('waktu_scan', `${today}T00:00:00`)
      .lte('waktu_scan', `${today}T23:59:59`)
      .single();
    
    if (!absensiError && existingAbsensi) {
      return res.status(400).json({ 
        message: 'Anda sudah melakukan absensi untuk jam pelajaran ini' 
      });
    }
    
    // Simpan data absensi
    const { data: absensi, error: insertError } = await supabase
      .from('absensi')
      .insert([{
        guru_id: guruId,
        kelas_id: kelas.id,
        jam_ke: jamKe,
        waktu_scan: now.toISOString()
      }])
      .single();
    
    if (insertError) {
      throw insertError;
    }
    
    res.json({
      message: 'Absensi berhasil',
      absensi
    });
  } catch (error) {
    console.error('Scan absensi error:', error);
    res.status(500).json({ message: 'Terjadi kesalahan server' });
  }
});

// Endpoint untuk laporan absensi
app.get('/laporan', authenticateToken, async (req, res) => {
  const { tanggal, guruId, kelasId, jamKe, format } = req.query;
  
  try {
    let query = supabase
      .from('absensi')
      .select(`
        *,
        guru: guru_id (nama, nip),
        kelas: kelas_id (nama, tingkat, jurusan)
      `);
    
    // Filter berdasarkan parameter
    if (tanggal) {
      const startDate = `${tanggal}T00:00:00`;
      const endDate = `${tanggal}T23:59:59`;
      query = query
        .gte('waktu_scan', startDate)
        .lte('waktu_scan', endDate);
    }
    
    if (guruId) {
      query = query.eq('guru_id', guruId);
    }
    
    if (kelasId) {
      query = query.eq('kelas_id', kelasId);
    }
    
    if (jamKe) {
      query = query.eq('jam_ke', jamKe);
    }
    
    const { data: absensi, error } = await query;
    
    if (error) {
      throw error;
    }
    
    // Export ke Excel atau PDF jika diminta
    if (format === 'excel') {
      const fields = [
        'id',
        'guru.nama',
        'guru.nip',
        'kelas.nama',
        'kelas.tingkat',
        'kelas.jurusan',
        'jam_ke',
        'waktu_scan'
      ];
      
      const json2csvParser = new Parser({ fields });
      const csv = json2csvParser.parse(absensi);
      
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', 'attachment; filename=laporan_absensi.csv');
      return res.send(csv);
    } else if (format === 'pdf') {
      const doc = new jsPDF();
      
      // Header
      doc.setFontSize(18);
      doc.text('Laporan Absensi Guru', 105, 15, { align: 'center' });
      
      // Tabel
      let yPosition = 30;
      doc.setFontSize(12);
      doc.text('No', 10, yPosition);
      doc.text('Nama Guru', 30, yPosition);
      doc.text('Kelas', 80, yPosition);
      doc.text('Jam', 120, yPosition);
      doc.text('Waktu', 150, yPosition);
      
      yPosition += 10;
      absensi.forEach((item, index) => {
        doc.text(`${index + 1}`, 10, yPosition);
        doc.text(item.guru.nama, 30, yPosition);
        doc.text(`${item.kelas.tingkat} ${item.kelas.nama}`, 80, yPosition);
        doc.text(item.jam_ke.toString(), 120, yPosition);
        doc.text(new Date(item.waktu_scan).toLocaleString('id-ID'), 150, yPosition);
        yPosition += 10;
        
        // Tambah halaman baru jika sudah mencapai batas
        if (yPosition > 280) {
          doc.addPage();
          yPosition = 20;
        }
      });
      
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', 'attachment; filename=laporan_absensi.pdf');
      return res.send(doc.output());
    }
    
    res.json(absensi);
  } catch (error) {
    console.error('Get laporan error:', error);
    res.status(500).json({ message: 'Terjadi kesalahan server' });
  }
});

// Endpoint untuk reset device guru
app.post('/guru/reset-device/:guruId', authenticateToken, async (req, res) => {
  const { guruId } = req.params;
  
  // Cek apakah user adalah admin
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Hanya admin yang bisa reset device guru' });
  }
  
  try {
    // Get user_id dari guru
    const { data: guru, error: guruError } = await supabase
      .from('guru')
      .select('user_id')
      .eq('id', guruId)
      .single();
    
    if (guruError || !guru) {
      return res.status(404).json({ message: 'Guru tidak ditemukan' });
    }
    
    // Reset device_id
    const { error: updateError } = await supabase
      .from('users')
      .update({ device_id: null })
      .eq('id', guru.user_id);
    
    if (updateError) {
      throw updateError;
    }
    
    // Log audit
    await supabase
      .from('audit_log')
      .insert([{
        user_id: req.user.id,
        aksi: 'RESET_DEVICE',
        target_id: guruId,
        target_type: 'guru',
        detail: `Reset device untuk guru ID: ${guruId}`
      }]);
    
    res.json({ message: 'Device guru berhasil direset' });
  } catch (error) {
    console.error('Reset device error:', error);
    res.status(500).json({ message: 'Terjadi kesalahan server' });
  }
});

// Endpoint CRUD untuk Guru
app.get('/guru', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Hanya admin yang bisa mengakses data guru' });
  }
  
  try {
    const { data: guru, error } = await supabase
      .from('guru')
      .select(`
        *,
        user: user_id (username, device_id)
      `);
    
    if (error) {
      throw error;
    }
    
    res.json(guru);
  } catch (error) {
    console.error('Get guru error:', error);
    res.status(500).json({ message: 'Terjadi kesalahan server' });
  }
});

app.post('/guru', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Hanya admin yang bisa menambah data guru' });
  }
  
  const { nama, nip, email, no_hp, username, password } = req.body;
  
  try {
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Buat user
    const { data: user, error: userError } = await supabase
      .from('users')
      .insert([{
        username,
        password: hashedPassword,
        role: 'guru'
      }])
      .single();
    
    if (userError) {
      throw userError;
    }
    
    // Buat guru
    const { data: guru, error: guruError } = await supabase
      .from('guru')
      .insert([{
        user_id: user.id,
        nama,
        nip,
        email,
        no_hp
      }])
      .single();
    
    if (guruError) {
      // Rollback user jika gagal membuat guru
      await supabase.from('users').delete().eq('id', user.id);
      throw guruError;
    }
    
    // Log audit
    await supabase
      .from('audit_log')
      .insert([{
        user_id: req.user.id,
        aksi: 'CREATE',
        target_id: guru.id,
        target_type: 'guru',
        detail: `Menambah guru baru: ${nama}`
      }]);
    
    res.status(201).json({
      message: 'Guru berhasil ditambahkan',
      guru: {
        ...guru,
        user: {
          username: user.username
        }
      }
    });
  } catch (error) {
    console.error('Create guru error:', error);
    res.status(500).json({ message: 'Terjadi kesalahan server' });
  }
});

app.delete('/guru/:guruId', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Hanya admin yang bisa menghapus data guru' });
  }
  
  const { guruId } = req.params;
  
  try {
    // Get user_id dari guru
    const { data: guru, error: guruError } = await supabase
      .from('guru')
      .select('user_id')
      .eq('id', guruId)
      .single();
    
    if (guruError || !guru) {
      return res.status(404).json({ message: 'Guru tidak ditemukan' });
    }
    
    // Hapus guru
    const { error: deleteGuruError } = await supabase
      .from('guru')
      .delete()
      .eq('id', guruId);
    
    if (deleteGuruError) {
      throw deleteGuruError;
    }
    
    // Hapus user
    const { error: deleteUserError } = await supabase
      .from('users')
      .delete()
      .eq('id', guru.user_id);
    
    if (deleteUserError) {
      throw deleteUserError;
    }
    
    // Log audit
    await supabase
      .from('audit_log')
      .insert([{
        user_id: req.user.id,
        aksi: 'DELETE',
        target_id: guruId,
        target_type: 'guru',
        detail: `Menghapus guru ID: ${guruId}`
      }]);
    
    res.json({ message: 'Guru berhasil dihapus' });
  } catch (error) {
    console.error('Delete guru error:', error);
    res.status(500).json({ message: 'Terjadi kesalahan server' });
  }
});

// Endpoint CRUD untuk Kelas
app.get('/kelas', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Hanya admin yang bisa mengakses data kelas' });
  }
  
  try {
    const { data: kelas, error } = await supabase
      .from('kelas')
      .select('*');
    
    if (error) {
      throw error;
    }
    
    res.json(kelas);
  } catch (error) {
    console.error('Get kelas error:', error);
    res.status(500).json({ message: 'Terjadi kesalahan server' });
  }
});

app.post('/kelas', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Hanya admin yang bisa menambah data kelas' });
  }
  
  const { nama, tingkat, jurusan } = req.body;
  
  try {
    // Generate QR token unik
    const qrToken = require('crypto').randomBytes(16).toString('hex');
    
    // Buat kelas
    const { data: kelas, error } = await supabase
      .from('kelas')
      .insert([{
        nama,
        tingkat,
        jurusan,
        qr_token: qrToken
      }])
      .single();
    
    if (error) {
      throw error;
    }
    
    // Log audit
    await supabase
      .from('audit_log')
      .insert([{
        user_id: req.user.id,
        aksi: 'CREATE',
        target_id: kelas.id,
        target_type: 'kelas',
        detail: `Menambah kelas baru: ${tingkat} ${nama}`
      }]);
    
    res.status(201).json({
      message: 'Kelas berhasil ditambahkan',
      kelas
    });
  } catch (error) {
    console.error('Create kelas error:', error);
    res.status(500).json({ message: 'Terjadi kesalahan server' });
  }
});

app.delete('/kelas/:kelasId', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Hanya admin yang bisa menghapus data kelas' });
  }
  
  const { kelasId } = req.params;
  
  try {
    // Hapus kelas
    const { error } = await supabase
      .from('kelas')
      .delete()
      .eq('id', kelasId);
    
    if (error) {
      throw error;
    }
    
    // Log audit
    await supabase
      .from('audit_log')
      .insert([{
        user_id: req.user.id,
        aksi: 'DELETE',
        target_id: kelasId,
        target_type: 'kelas',
        detail: `Menghapus kelas ID: ${kelasId}`
      }]);
    
    res.json({ message: 'Kelas berhasil dihapus' });
  } catch (error) {
    console.error('Delete kelas error:', error);
    res.status(500).json({ message: 'Terjadi kesalahan server' });
  }
});

// Endpoint CRUD untuk Jadwal
app.get('/jadwal', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Hanya admin yang bisa mengakses data jadwal' });
  }
  
  try {
    const { data: jadwal, error } = await supabase
      .from('jadwal')
      .select(`
        *,
        guru: guru_id (nama, nip),
        kelas: kelas_id (nama, tingkat, jurusan)
      `);
    
    if (error) {
      throw error;
    }
    
    res.json(jadwal);
  } catch (error) {
    console.error('Get jadwal error:', error);
    res.status(500).json({ message: 'Terjadi kesalahan server' });
  }
});

// Endpoint untuk mendapatkan jadwal berdasarkan guru ID
app.get('/jadwal/guru/:guruId', authenticateToken, async (req, res) => {
  const { guruId } = req.params;
  
  // Cek apakah user adalah guru yang bersangkutan atau admin
  if (req.user.role !== 'admin' && req.user.guru.id !== guruId) {
    return res.status(403).json({ message: 'Anda tidak memiliki akses ke jadwal ini' });
  }
  
  try {
    const { data: jadwal, error } = await supabase
      .from('jadwal')
      .select(`
        *,
        guru: guru_id (nama, nip),
        kelas: kelas_id (nama, tingkat, jurusan)
      `)
      .eq('guru_id', guruId);
    
    if (error) {
      throw error;
    }
    
    res.json(jadwal);
  } catch (error) {
    console.error('Get jadwal by guru error:', error);
    res.status(500).json({ message: 'Terjadi kesalahan server' });
  }
});

app.post('/jadwal', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Hanya admin yang bisa menambah data jadwal' });
  }
  
  const { guru_id, kelas_id, hari, jam_ke, jam_mulai, jam_selesai, mata_pelajaran } = req.body;
  
  try {
    // Buat jadwal
    const { data: jadwal, error } = await supabase
      .from('jadwal')
      .insert([{
        guru_id,
        kelas_id,
        hari,
        jam_ke,
        jam_mulai,
        jam_selesai,
        mata_pelajaran
      }])
      .single();
    
    if (error) {
      throw error;
    }
    
    // Log audit
    await supabase
      .from('audit_log')
      .insert([{
        user_id: req.user.id,
        aksi: 'CREATE',
        target_id: jadwal.id,
        target_type: 'jadwal',
        detail: `Menambah jadwal baru: ${mata_pelajaran} untuk kelas ${kelas_id}`
      }]);
    
    res.status(201).json({
      message: 'Jadwal berhasil ditambahkan',
      jadwal
    });
  } catch (error) {
    console.error('Create jadwal error:', error);
    res.status(500).json({ message: 'Terjadi kesalahan server' });
  }
});

app.delete('/jadwal/:jadwalId', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Hanya admin yang bisa menghapus data jadwal' });
  }
  
  const { jadwalId } = req.params;
  
  try {
    // Hapus jadwal
    const { error } = await supabase
      .from('jadwal')
      .delete()
      .eq('id', jadwalId);
    
    if (error) {
      throw error;
    }
    
    // Log audit
    await supabase
      .from('audit_log')
      .insert([{
        user_id: req.user.id,
        aksi: 'DELETE',
        target_id: jadwalId,
        target_type: 'jadwal',
        detail: `Menghapus jadwal ID: ${jadwalId}`
      }]);
    
    res.json({ message: 'Jadwal berhasil dihapus' });
  } catch (error) {
    console.error('Delete jadwal error:', error);
    res.status(500).json({ message: 'Terjadi kesalahan server' });
  }
});

// Endpoint untuk mendapatkan data absensi berdasarkan guru ID
app.get('/absensi/guru/:guruId', authenticateToken, async (req, res) => {
  const { guruId } = req.params;
  
  // Cek apakah user adalah guru yang bersangkutan atau admin
  if (req.user.role !== 'admin' && req.user.guru.id !== guruId) {
    return res.status(403).json({ message: 'Anda tidak memiliki akses ke data absensi ini' });
  }
  
  try {
    const { data: absensi, error } = await supabase
      .from('absensi')
      .select(`
        *,
        kelas: kelas_id (nama, tingkat, jurusan)
      `)
      .eq('guru_id', guruId)
      .order('waktu_scan', { ascending: false });
    
    if (error) {
      throw error;
    }
    
    res.json(absensi);
  } catch (error) {
    console.error('Get absensi by guru error:', error);
    res.status(500).json({ message: 'Terjadi kesalahan server' });
  }
});

// Endpoint CRUD untuk Users
app.get('/users', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Hanya admin yang bisa mengakses data users' });
  }
  
  try {
    const { data: users, error } = await supabase
      .from('users')
      .select(`
        *,
        guru: guru_id (id, nama, nip)
      `);
    
    if (error) {
      throw error;
    }
    
    res.json(users);
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ message: 'Terjadi kesalahan server' });
  }
});

app.delete('/users/:userId', authenticateToken, async (req, res) => {
  const { userId } = req.params;
  
  // Cek apakah user adalah admin
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Hanya admin yang bisa menghapus user' });
  }
  
  // Cegah hapus diri sendiri
  if (req.user.id === userId) {
    return res.status(400).json({ message: 'Tidak bisa menghapus akun sendiri' });
  }
  
  try {
    // Cek apakah user ada
    const { data: user, error: userError } = await supabase
      .from('users')
      .select('*')
      .eq('id', userId)
      .single();
    
    if (userError || !user) {
      return res.status(404).json({ message: 'User tidak ditemukan' });
    }
    
    // Hapus user
    const { error: deleteError } = await supabase
      .from('users')
      .delete()
      .eq('id', userId);
    
    if (deleteError) {
      throw deleteError;
    }
    
    // Log audit
    await supabase
      .from('audit_log')
      .insert([{
        user_id: req.user.id,
        aksi: 'DELETE',
        target_id: userId,
        target_type: 'user',
        detail: `Menghapus user: ${user.username}`
      }]);
    
    res.json({ message: 'User berhasil dihapus' });
  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({ message: 'Terjadi kesalahan server' });
  }
});

// Endpoint untuk ganti password
app.post('/auth/change-password', authenticateToken, async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  const userId = req.user.id;
  
  try {
    // Get user
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('id', userId)
      .single();
    
    if (error || !user) {
      return res.status(404).json({ message: 'User tidak ditemukan' });
    }
    
    // Verifikasi password lama
    const passwordMatch = await bcrypt.compare(oldPassword, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ message: 'Password lama salah' });
    }
    
    // Hash password baru
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    
    // Update password
    const { error: updateError } = await supabase
      .from('users')
      .update({ password: hashedPassword })
      .eq('id', userId);
    
    if (updateError) {
      throw updateError;
    }
    
    // Log audit
    await supabase
      .from('audit_log')
      .insert([{
        user_id: userId,
        aksi: 'CHANGE_PASSWORD',
        target_id: userId,
        target_type: 'user',
        detail: 'Mengganti password'
      }]);
    
    res.json({ message: 'Password berhasil diubah' });
  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({ message: 'Terjadi kesalahan server' });
  }
});

// Endpoint untuk mendapatkan audit log
app.get('/audit-log', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Hanya admin yang bisa mengakses audit log' });
  }
  
  try {
    const { data: logs, error } = await supabase
      .from('audit_log')
      .select('*')
      .order('created_at', { ascending: false })
      .limit(100);
    
    if (error) {
      throw error;
    }
    
    res.json(logs);
  } catch (error) {
    console.error('Get audit log error:', error);
    res.status(500).json({ message: 'Terjadi kesalahan server' });
  }
});

// Test Supabase connection
app.get('/test-supabase', async (req, res) => {
  try {
    console.log('=== Testing Supabase Connection ===');
    console.log('SUPABASE_URL:', process.env.SUPABASE_URL);
    console.log('SUPABASE_KEY:', process.env.SUPABASE_KEY ? '***' : 'NOT FOUND');
    
    // Test koneksi dengan query yang lebih sederhana
    console.log('Testing simple query...');
    const { data, error, status } = await supabase
      .from('users')
      .select('*')
      .limit(1);
    
    console.log('Query result:');
    console.log('Data:', data);
    console.log('Error:', error);
    console.log('Status:', status);
    
    if (error) {
      console.error('Supabase error:', error);
      return res.status(500).json({ 
        error: error.message,
        details: error,
        status: status
      });
    }
    
    console.log('Supabase connection successful!');
    console.log('===================================');
    
    res.json({ 
      message: 'Connected to Supabase successfully', 
      data: data,
      status: status,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Test route error:', err);
    res.status(500).json({ error: err.message, stack: err.stack });
  }
});

// Create first admin
app.get('/create-admin', async (req, res) => {
  try {
    console.log('=== Creating Admin User ===');
    
    // Check if admin already exists
    const { data: existingAdmin } = await supabase
      .from('users')
      .select('*')
      .eq('username', 'admin')
      .single();
    
    if (existingAdmin) {
      console.log('Admin already exists');
      return res.json({ message: 'Admin already exists' });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash('admin123', 10);
    console.log('Password hashed');
    
    // Create admin user
    const { data: user, error: userError } = await supabase
      .from('users')
      .insert([{
        username: 'admin',
        password: hashedPassword,
        role: 'admin'
      }])
      .single();
    
    if (userError) {
      console.error('Error creating admin:', userError);
      throw userError;
    }
    
    console.log('Admin created successfully:', user);
    console.log('============================');
    
    res.json({ 
      message: 'Admin created successfully', 
      username: 'admin', 
      password: 'admin123',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Create admin error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Serve static files
app.use(express.static('public'));

// Default route
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => console.log(`Listening on ${PORT}`));
