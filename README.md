# Gemini-BBP
Repository Gemini Bug Bounty Program

## 📋 Deskripsi
Halaman pengumpulan data kerentanan keamanan pada Gemini AI. Platform ini memungkinkan peneliti keamanan dan pengguna untuk melaporkan kerentanan yang ditemukan pada sistem Gemini.

## 🚀 Fitur
- 📝 Form pelaporan kerentanan yang lengkap
- 🔍 Klasifikasi tingkat keparahan (Critical, High, Medium, Low, Info)
- 📊 Dashboard statistik kerentanan
- 💾 Penyimpanan data lokal menggunakan localStorage
- 🎨 Antarmuka yang responsif dan modern
- 🔒 Kategori kerentanan yang komprehensif

## 🛠️ Cara Menggunakan
1. Buka file `index.html` di browser
2. Isi form pelaporan kerentanan dengan informasi yang lengkap
3. Pilih tingkat keparahan dan kategori kerentanan
4. Klik "Kirim Laporan" untuk menyimpan data
5. Lihat laporan kerentanan yang terkumpul di panel sebelah kanan

## 📂 Struktur
```
Gemini-BBP/
├── index.html          # Halaman utama pengumpulan data kerentanan
└── README.md           # Dokumentasi
```

## 💡 Informasi
Data kerentanan disimpan secara lokal di browser menggunakan localStorage. Untuk deployment produksi, disarankan untuk mengintegrasikan dengan backend dan database untuk penyimpanan yang lebih aman dan terpusat.

## 🔐 Kategori Kerentanan yang Didukung
- Injection (SQL, Command, etc.)
- Cross-Site Scripting (XSS)
- Cross-Site Request Forgery (CSRF)
- Authentication Bypass
- Authorization Issues
- Sensitive Data Exposure
- Server-Side Request Forgery (SSRF)
- Lainnya

## 📧 Kontribusi
Silakan laporkan kerentanan yang Anda temukan melalui halaman ini atau buat issue di repository GitHub.
