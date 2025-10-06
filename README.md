# 🛡️ Cybersecurity Lab Documentation by Lubellion

Dokumentasi lab eksperimen penetration testing dan network sec## 📝 Menambah Lab Report Baru

Untuk menambah lab report baru, edit file `src/data/articles.js`:

```javascript
{
  id: 4,
  title: "Lab Report: [Judul Eksperimen]",
  slug: "lab-experiment-slug",
  excerpt: "Brief description of the experiment...",
  category: "Lab Report",
  author: "Lubellion",
  date: "2024-10-06",
  readTime: 20,
  image: "URL_GAMBAR",
  content: `
    # Lab Report: [Judul]
    
    **Experimenter:** Lubellion
    **Date:** [Tanggal]
    **Lab Environment:** [Description]
    
    ## Executive Summary
    [Ringkasan eksperimen]
    
    ## Lab Setup
    [Environment configuration]
    
    ## Methodology
    [Langkah-langkah eksperimen]
    
    ## Results
    [Hasil dan findings]
    
    ## Conclusion
    [Kesimpulan dan rekomendasi]
  `
}
```

## 👤 About Lubellion

Lubellion adalah cybersecurity researcher yang fokus pada:
- Penetration Testing & Vulnerability Assessment
- Network Security & Intrusion Detection
- Web Application Security Testing
- Security Research & Documentation

**Contact:**
- 📧 Email: lubellion@cybersec.lab
- 💻 GitHub: github.com/lubellion
- 💼 LinkedIn: linkedin.com/in/lubellion menggunakan React + Vite. Platform ini mendokumentasikan hasil penelitian dan eksperimen dalam bidang ethical hacking secara sistematis.

![React](https://img.shields.io/badge/React-18.3.1-blue)
![Vite](https://img.shields.io/badge/Vite-5.4.1-purple)
![License](https://img.shields.io/badge/License-Educational-green)

## 📋 Deskripsi

Website dokumentasi ini berisi lab reports lengkap untuk:
- � **Metasploitable 2 Penetration Testing** - Comprehensive exploitation dan vulnerability assessment
- 🌐 **Nmap Network Scanning** - Advanced reconnaissance dan service detection techniques  
- �️ **Snort IDS Implementation** - Intrusion detection system setup dan custom rule development

## ✨ Fitur Dokumentasi

- ✅ **Lab Report Format** - Dokumentasi sistematis dengan metodologi lengkap
- ✅ **Experimenter Profile** - Informasi tentang Lubellion (researcher)
- ✅ **Dark Theme** - Professional theme untuk technical documentation
- ✅ **Markdown Rendering** - Format lab report dengan code blocks dan tables
- ✅ **Search & Filter** - Cari lab reports dengan mudah
- ✅ **Responsive Design** - Optimal di semua devices

## 🔬 Lab Experiments

### 1. Metasploitable 2 Penetration Testing
Dokumentasi lengkap eksperimen penetration testing meliputi:
- Reconnaissance dan scanning dengan Nmap
- Exploitation menggunakan Metasploit Framework
- Post-exploitation dan privilege escalation
- Vulnerability assessment dan remediation recommendations

### 2. Nmap Network Scanning
Comprehensive network reconnaissance experiments:
- Various scanning techniques (SYN, Connect, UDP, etc.)
- Service version detection dan OS fingerprinting
- NSE script scanning untuk vulnerability assessment
- Firewall evasion techniques
- Performance analysis dan timing templates

### 3. Snort IDS Implementation
Real-world intrusion detection system deployment:
- Installation dan configuration dari scratch
- Custom rule development untuk various attacks
- Performance tuning dan optimization
- Integration dengan analysis tools (Barnyard2, BASE, ELK)
- Attack simulation dan validation testing

## 🚀 Teknologi yang Digunakan

- **React 18** - Modern UI library
- **Vite** - Lightning-fast build tool
- **React Router** - Client-side routing
- **React Markdown** - Markdown rendering untuk lab reports
- **CSS3** - Custom styling dengan CSS variables

## 📦 Instalasi

### Prerequisites
- Node.js (v16 atau lebih baru)
- npm atau yarn

### Langkah-langkah

1. Clone repository ini:
\`\`\`bash
git clone <repository-url>
cd "Blog Ethical Hacking"
\`\`\`

2. Install dependencies:
\`\`\`bash
npm install
\`\`\`

3. Jalankan development server:
\`\`\`bash
npm run dev
\`\`\`

4. Buka browser dan akses:
\`\`\`
http://localhost:5173
\`\`\`

## 🏗️ Struktur Project

\`\`\`
Blog Ethical Hacking/
├── src/
│   ├── components/          # Komponen React
│   │   ├── Header.jsx
│   │   ├── Footer.jsx
│   │   └── ArticleCard.jsx
│   ├── pages/              # Halaman aplikasi
│   │   ├── Home.jsx
│   │   ├── ArticleDetail.jsx
│   │   └── About.jsx
│   ├── data/               # Data artikel
│   │   └── articles.js
│   ├── App.jsx             # Main App component
│   ├── main.jsx            # Entry point
│   └── index.css           # Global styles
├── index.html              # HTML template
├── package.json            # Dependencies
└── vite.config.js          # Vite configuration
\`\`\`

## 📝 Menambah Artikel Baru

Untuk menambah artikel baru, edit file \`src/data/articles.js\`:

\`\`\`javascript
{
  id: 7,
  title: "Judul Artikel",
  slug: "judul-artikel",
  excerpt: "Ringkasan singkat artikel...",
  category: "Kategori",
  author: "Nama Penulis",
  date: "2024-10-06",
  readTime: 10,
  image: "URL_GAMBAR",
  content: \`
    # Heading 1
    ## Heading 2
    
    Konten artikel dalam format Markdown...
  \`
}
\`\`\`

## 🎨 Kustomisasi Theme

Edit variabel CSS di \`src/index.css\`:

\`\`\`css
:root {
  --bg-primary: #0a0e27;
  --bg-secondary: #141b3d;
  --accent: #00ff88;
  /* ... variabel lainnya */
}
\`\`\`

## 📚 Topik Artikel yang Tersedia

1. **Pengenalan Ethical Hacking** - Dasar-dasar ethical hacking
2. **Reconnaissance** - Teknik information gathering
3. **Network Scanning dengan Nmap** - Tutorial Nmap lengkap
4. **OWASP Top 10** - Kerentanan web application
5. **Metasploit Framework** - Exploitation tool
6. **Social Engineering** - Teknik manipulasi psikologis

## ⚠️ Disclaimer

**PENTING:** Semua informasi dalam blog ini adalah untuk **tujuan edukasi** saja!

- ✅ Selalu dapatkan izin tertulis sebelum melakukan penetration testing
- ❌ Jangan gunakan untuk aktivitas ilegal
- ✅ Patuhi hukum dan regulasi yang berlaku
- ✅ Gunakan untuk meningkatkan keamanan, bukan merusaknya

## 🔧 Build untuk Production

\`\`\`bash
npm run build
\`\`\`

File production akan ada di folder \`dist/\`.

## 🚀 Preview Production Build

\`\`\`bash
npm run preview
\`\`\`

## 📖 Resources Tambahan

- [OWASP](https://owasp.org) - Web Application Security
- [Offensive Security](https://www.offensive-security.com) - OSCP Certification
- [HackTheBox](https://www.hackthebox.com) - Hands-on Practice
- [TryHackMe](https://tryhackme.com) - Learning Platform
- [PortSwigger Academy](https://portswigger.net/web-security) - Free Training

## 📄 License

Project ini dibuat untuk tujuan edukasi dalam mata kuliah Ethical Hacking.

## 👨‍💻 Kontributor

Dibuat dengan ❤️ untuk pembelajaran ethical hacking

---

**⚡ Happy Hacking (Ethically)! ⚡**
