Tentu, saya akan buatkan file README.md untuk proyek ini. File ini akan berisi panduan lengkap tentang instalasi, penggunaan, dan informasi penting lainnya tentang aplikasi Sistem Absensi Guru.

```markdown
# Sistem Absensi Guru

Aplikasi web berbasis QR Code untuk pencatatan absensi guru dengan dua peran: Admin dan Guru.

## Fitur

### Admin
- Login sebagai admin
- CRUD data guru dan jadwal pelajaran
- Generate 1 QR Code unik untuk setiap kelas (printable)
- Kelola User ID & Password guru
- Reset akun guru yang melanggar aturan
- Lihat Laporan Absensi dengan filter (per tanggal, guru, kelas, jam pelajaran)
- Laporan bisa export ke Excel/PDF
- Dashboard berisi tabel absensi & grafik ringkasan

### Guru (Mobile-first)
- Login sebagai guru dengan User ID & Password
- Login hanya bisa dilakukan di HP pertama kali yang dipakai (device-binding)
- Scan QR Code kelas di setiap jam pelajaran untuk absen
- Data absensi disimpan: guru_id, kelas_id, jam_ke, waktu scan
- Riwayat absensi bisa dilihat oleh guru sendiri
- Sistem mencegah double scan dalam 1 jam pelajaran

## Teknologi yang Digunakan

- **Frontend**: HTML, CSS, JavaScript, jQuery, Chart.js, html5-qrcode
- **Backend**: Node.js, Express.js
- **Database**: Supabase (PostgreSQL)
- **Autentikasi**: JWT (JSON Web Tokens)
- **Library**: bcryptjs, qrcode, json2csv, jsPDF
- **Styling**: Tailwind CSS

## Instalasi

### Prasyarat
- Node.js (v14 atau lebih tinggi)
- Akun Supabase (https://supabase.com)

### Langkah-langkah

1. **Clone atau download repositori ini**
   ```bash
   git clone https://github.com/username/absensi-guru.git
   cd absensi-guru
   ```

2. **Instal dependensi**
   ```bash
   npm install
   ```

3. **Konfigurasi environment variables**
   - Buat file `.env` di root proyek
   - Salin konten dari `.env.example` dan sesuaikan dengan konfigurasi Supabase Anda:
   ```
   SUPABASE_URL=your_supabase_url_here
   SUPABASE_KEY=your_supabase_key_here
   JWT_SECRET=your_jwt_secret_here
   PORT=3000
   ```

4. **Setup database di Supabase**
   - Buat proyek baru di Supabase
   - Dapatkan URL dan Key dari Settings > API
   - Buka SQL Editor di Supabase Dashboard
   - Jalankan SQL script yang ada di file `database.sql`

5. **Jalankan aplikasi**
   ```bash
   npm start
   ```

6. **Akses aplikasi**
   - Buka browser dan akses `http://localhost:3000`
   - Anda akan diarahkan ke halaman login

## Struktur Database

### Tabel Users
```sql
CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  username VARCHAR(50) UNIQUE NOT NULL,
  password VARCHAR(255) NOT NULL,
  role VARCHAR(10) NOT NULL CHECK (role IN ('admin', 'guru')),
  device_id VARCHAR(255),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

### Tabel Guru
```sql
CREATE TABLE guru (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  nama VARCHAR(100) NOT NULL,
  nip VARCHAR(20) UNIQUE,
  email VARCHAR(100),
  no_hp VARCHAR(15),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

### Tabel Kelas
```sql
CREATE TABLE kelas (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  nama VARCHAR(50) NOT NULL,
  tingkat VARCHAR(10) NOT NULL,
  jurusan VARCHAR(50),
  qr_token VARCHAR(255) UNIQUE NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

### Tabel Jadwal
```sql
CREATE TABLE jadwal (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  guru_id UUID REFERENCES guru(id) ON DELETE CASCADE,
  kelas_id UUID REFERENCES kelas(id) ON DELETE CASCADE,
  hari VARCHAR(10) NOT NULL,
  jam_ke INTEGER NOT NULL,
  jam_mulai TIME NOT NULL,
  jam_selesai TIME NOT NULL,
  mata_pelajaran VARCHAR(100) NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

### Tabel Absensi
```sql
CREATE TABLE absensi (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  guru_id UUID REFERENCES guru(id) ON DELETE CASCADE,
  kelas_id UUID REFERENCES kelas(id) ON DELETE CASCADE,
  jam_ke INTEGER NOT NULL,
  waktu_scan TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

### Tabel Audit Log
```sql
CREATE TABLE audit_log (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  aksi VARCHAR(50) NOT NULL,
  target_id UUID,
  target_type VARCHAR(50),
  detail TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

## Struktur Folder

```
absensi-guru/
├── public/
│   ├── index.html
│   ├── login.html
│   ├── admin-dashboard.html
│   └── guru-dashboard.html
├── server.js
├── package.json
├── .env
└── README.md
```

## API Endpoints

### Autentikasi
- `POST /auth/login` - Login user
- `POST /auth/signup` - Registrasi user baru
- `GET /auth/me` - Get data user berdasarkan token
- `POST /auth/change-password` - Ganti password

### Kelas
- `GET /kelas` - Get semua data kelas (admin only)
- `POST /kelas` - Tambah kelas baru (admin only)
- `DELETE /kelas/:kelasId` - Hapus kelas (admin only)
- `GET /kelas/qrcode/:kelasId` - Generate QR Code untuk kelas (admin only)

### Guru
- `GET /guru` - Get semua data guru (admin only)
- `POST /guru` - Tambah guru baru (admin only)
- `DELETE /guru/:guruId` - Hapus guru (admin only)
- `POST /guru/reset-device/:guruId` - Reset device guru (admin only)

### Jadwal
- `GET /jadwal` - Get semua data jadwal (admin only)
- `GET /jadwal/guru/:guruId` - Get jadwal berdasarkan guru ID
- `POST /jadwal` - Tambah jadwal baru (admin only)
- `DELETE /jadwal/:jadwalId` - Hapus jadwal (admin only)

### Absensi
- `POST /absen/scan` - Scan QR Code untuk absensi
- `GET /absensi/guru/:guruId` - Get riwayat absensi guru
- `GET /laporan` - Get laporan absensi dengan filter

### Users
- `GET /users` - Get semua data user (admin only)
- `DELETE /users/:userId` - Hapus user (admin only)

### Audit Log
- `GET /audit-log` - Get audit log (admin only)

## Penggunaan

### Untuk Admin
1. Login dengan username dan password admin
2. Tambah data guru, kelas, dan jadwal pelajaran
3. Generate QR Code untuk setiap kelas dan cetak/tempel di kelas
4. Monitor absensi guru melalui dashboard
5. Generate laporan absensi dalam format Excel atau PDF

### Untuk Guru
1. Login dengan username dan password yang diberikan admin
2. Aplikasi akan terikat dengan device yang digunakan untuk pertama kali
3. Pada jam pelajaran, scan QR Code yang ada di kelas untuk melakukan absensi
4. Lihat riwayat absensi pribadi
5. Ganti password jika diperlukan

## Troubleshooting

### Masalah Umum
1. **Error "Cannot find module"** - Pastikan semua dependensi sudah terinstal dengan `npm install`
2. **Error "Connection refused"** - Pastikan server sudah berjalan dan port tidak digunakan oleh aplikasi lain
3. **Error "Invalid token"** - Pastikan token masih valid dan belum kadaluarsa
4. **QR Code tidak terbaca** - Pastikan QR Code tercetak dengan jelas dan tidak rusak

### Reset Device Guru
Jika guru ingin ganti device atau lupa password, admin bisa mereset device ID melalui menu Kelola Akun > Data Guru > Reset Device.

### Backup Data
Pastikan untuk melakukan backup data secara berkala melalui fitur export yang tersedia.

## Kontribusi

Kontribusi sangat diperlukan untuk pengembangan proyek ini. Silakan fork repositori ini dan buat pull request untuk fitur baru atau perbaikan bug.

## Lisensi

Proyek ini dilisensikan under MIT License - lihat file [LICENSE](LICENSE) untuk detailnya.

## Dukungan

Jika Anda mengalami masalah atau memiliki pertanyaan, silakan buka issue di repositori ini atau hubungi tim pengembang.
```

Simpan file ini dengan nama `README.md` di folder utama proyek Anda (`C:\Users\ok_ru\absensi-guru\README.md`). File ini akan memberikan panduan lengkap tentang proyek ini untuk siapa saja yang ingin menggunakan atau mengembangkan aplikasi ini.